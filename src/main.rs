use serenity::async_trait;
use serenity::model::channel::Message;
use serenity::model::gateway::Ready;
use serenity::prelude::*;
use serde::Deserialize;
use std::fs;
use anyhow::Result;
use rusqlite::{params, Connection, OptionalExtension};
use std::sync::{Arc, Mutex};
use std::collections::HashMap;

const MAX_HISTORY_CHARS: usize = 2000; // Max characters for conversation history
const MAX_USER_DATA_CHARS: usize = 5000; // Max characters for user data collection

#[derive(Deserialize, Clone)]
struct Config {
    discord_token: String,
    openai_token: String,
    insult_channel_id: String,
}

struct Handler {
    config: Config,
    db: Arc<Mutex<Connection>>,
}

// Helper to manage conversation history string
fn append_to_history(current_history: &str, user_message: &str, ai_response: &str) -> String {
    let mut new_history = format!("{}\nUser: {}\nAI: {}", current_history, user_message, ai_response);
    if new_history.len() > MAX_HISTORY_CHARS {
        let start_index = new_history.len() - MAX_HISTORY_CHARS;
        new_history = new_history[start_index..].to_string();
        // Ensure we don't cut mid-line
        if let Some(first_newline) = new_history.find('\n') {
            new_history = new_history[first_newline+1..].to_string();
        }
    }
    new_history.trim().to_string()
}

#[async_trait]
impl EventHandler for Handler {
    async fn message(&self, ctx: Context, msg: Message) {
        // Store message data for all non-bot users regardless of channel
        if !msg.author.bot {
            let user_id_str = msg.author.id.to_string();
            let user_name = &msg.author.name;
            let user_text = &msg.content;
            
            // Store user message data in a separate block
            {
                let db_lock = self.db.lock().unwrap();
                
                // Get existing message data
                let existing_data: Option<String> = db_lock
                    .query_row(
                        "SELECT message_data FROM user_data WHERE user_id = ?1",
                        params![&user_id_str],
                        |row| row.get::<_, String>(0),
                    )
                    .optional()
                    .unwrap_or(None);
                
                // Append new message and truncate if needed
                let timestamp = chrono::Utc::now().timestamp();
                let new_entry = format!("[{}] {}: {}", timestamp, user_name, user_text);
                
                let updated_data = match existing_data {
                    Some(data) => {
                        let mut combined = format!("{}
{}", data, new_entry);
                        if combined.len() > MAX_USER_DATA_CHARS {
                            // Keep only the newest data
                            let excess = combined.len() - MAX_USER_DATA_CHARS;
                            // Find first newline after excess
                            if let Some(pos) = combined[excess..].find('\n') {
                                combined = combined[(excess + pos + 1)..].to_string();
                            } else {
                                combined = combined[excess..].to_string();
                            }
                        }
                        combined
                    },
                    None => new_entry,
                };
                
                // Update the database
                db_lock
                    .execute(
                        "INSERT OR REPLACE INTO user_data (user_id, message_data, last_updated) VALUES (?1, ?2, ?3)",
                        params![&user_id_str, updated_data, timestamp],
                    )
                    .expect("Failed to update user data");
            } // MutexGuard is dropped here
        }
        
        // Only process insults in the configured channel
        if msg.channel_id.to_string() != self.config.insult_channel_id || msg.author.bot {
            return;
        }
        // Don't insult yourself
        if msg.mentions_me(&ctx.http).await.unwrap_or(false) {
            return;
        }

        let user_id_str = msg.author.id.to_string();
        let user_name = &msg.author.name;
        let user_text = &msg.content;

        // Step 1: Read history from DB (with a synchronous block that drops the lock before await)
        // Get history from DB in a separate block to ensure MutexGuard is dropped before await
        let current_history = {
            // Synchronous block to ensure lock is released before any await
            let db_lock = self.db.lock().unwrap();
            let history_opt: Option<String> = db_lock
                .query_row(
                    "SELECT history FROM user_history WHERE user_id = ?1",
                    params![&user_id_str],
                    |row| row.get::<_, String>(0),
                )
                .optional()
                .unwrap_or(None);
            // Return history from the block, which drops the lock
            history_opt.unwrap_or_default()
        }; // MutexGuard is dropped here

        // Get user data for more personalized insults
        let user_data = {
            let db_lock = self.db.lock().unwrap();
            let data_opt: Option<String> = db_lock
                .query_row(
                    "SELECT message_data FROM user_data WHERE user_id = ?1",
                    params![&user_id_str],
                    |row| row.get::<_, String>(0),
                )
                .optional()
                .unwrap_or(None);
            data_opt.unwrap_or_default()
        };
        
        // Step 2: Generate insult (async call with no locks held)
        let insult = match get_insult(&self.config.openai_token, user_name, user_text, &current_history, &user_data).await {
            Ok(insult) => {
                // Step 3: Update history in DB (again as a synchronous block)
                {
                    let db_lock = self.db.lock().unwrap();
                    let updated_history = append_to_history(&current_history, user_text, &insult);
                    db_lock
                        .execute(
                            "INSERT OR REPLACE INTO user_history (user_id, history) VALUES (?1, ?2)",
                            params![&user_id_str, updated_history],
                        )
                        .expect("Failed to update history");
                } // MutexGuard is dropped here
                insult
            },
            Err(e) => {
                eprintln!("Error getting insult: {}", e);
                "I'm too flustered to insult you right now!".to_string()
            },
        };

        // Step 4: Send the insult (async call with no locks held)
        if let Err(why) = msg.channel_id.say(&ctx.http, &insult).await {
            eprintln!("Error sending message: {:?}", why);
        }
    }

    async fn ready(&self, _: Context, ready: Ready) {
        println!("{} is connected!", ready.user.name);
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let config: Config = serde_json::from_str(&fs::read_to_string("config.json")?)?;
    
    let conn = Connection::open("user_history.db")?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS user_history (
            user_id TEXT PRIMARY KEY,
            history TEXT NOT NULL
        )",
        [],
    )?;
    
    // Add a new table to store user data collected from all messages
    conn.execute(
        "CREATE TABLE IF NOT EXISTS user_data (
            user_id TEXT PRIMARY KEY,
            message_data TEXT NOT NULL,
            last_updated INTEGER NOT NULL
        )",
        [],
    )?;

    let handler_config = config.clone(); // Clone config for the handler
    let handler = Handler {
        config: handler_config,
        db: Arc::new(Mutex::new(conn)),
    };

    let mut client = Client::builder(&config.discord_token, GatewayIntents::all())
        .event_handler(handler)
        .await?;

    if let Err(why) = client.start().await {
        eprintln!("Client error: {:?}", why);
    }
    Ok(())
}

async fn get_insult(openai_token: &str, username: &str, user_text: &str, history: &str, user_data: &str) -> Result<String> {
    let mut messages = vec![
        serde_json::json!({ "role": "system", "content": "You are an AI that delivers insults inspired by 4chan culture. Your insults should be edgy, sarcastic, and use typical 4chan vernacular and meme references. Include greentext style ('>') occasionally, use terms like 'anon', 'OP', 'based', 'cringe', etc. Make insults personal based on what the user says and their message history. Be creative and varied but maintain that distinct 4chan tone. Keep it offensive but avoid actual hate speech, slurs, or discriminatory content." }),
    ];

    if !history.is_empty() {
        messages.push(serde_json::json!({ "role": "assistant", "content": format!("Here's our previous conversation:\n{}", history) }));
    }
    
    // Add user data if available
    if !user_data.is_empty() {
        messages.push(serde_json::json!({ "role": "system", "content": format!("Here's additional data about this user from their previous messages across the server. Use this to craft a more personalized insult:\n{}", user_data) }));
    }

    messages.push(serde_json::json!({ "role": "user", "content": format!("My name is {}. My latest message to you was: '{}'. Give me a 4chan-style insult that would be posted on a board like /b/ or /r9k/. Make it personal based on my message, our conversation history, and my message patterns across the server. Reference specific things I've said in the past if relevant. Don't hold back, anon.", username, user_text) }));

    let client = reqwest::Client::new();
    let res = client
        .post("https://api.openai.com/v1/chat/completions")
        .bearer_auth(openai_token)
        .json(&serde_json::json!({
            "model": "gpt-3.5-turbo",
            "messages": messages,
            "max_tokens": 100, // Increased max_tokens for potentially longer contextual insults
            "temperature": 0.8 // Slightly higher temperature for more creative/varied insults
        }))
        .send()
        .await?;

    let res_json: serde_json::Value = res.json().await?;
    
    if let Some(choice) = res_json.get("choices").and_then(|c| c.as_array()).and_then(|arr| arr.get(0)) {
        if let Some(message) = choice.get("message").and_then(|m| m.get("content")) {
            if let Some(insult_str) = message.as_str() {
                return Ok(insult_str.trim().to_string());
            }
        }
    }
    Ok("You are so bland, I can't even come up with an insult for you.".to_string())
}
