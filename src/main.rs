use serenity::async_trait;
use serenity::model::channel::Message;
use serenity::model::gateway::Ready;
use serenity::model::id::ChannelId;
use serenity::prelude::*;
use serde::Deserialize;
use std::fs;
use anyhow::Result;
use rusqlite::{params, Connection, OptionalExtension};
use reqwest;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
// Removed unused HashMap import

const MAX_HISTORY_CHARS: usize = 2000; // Max characters for conversation history
const MAX_USER_DATA_CHARS: usize = 5000; // Max characters for user data collection

#[derive(Deserialize, Clone)]
struct Config {
    discord_token: String,
    openai_token: String,
    insult_channel_id: String,
    admin_channel_id: String,
}

struct Handler {
    config: Config,
    db: Arc<Mutex<Connection>>,
}

impl Handler {
    // Process commands from the admin channel
    async fn process_admin_command(&self, ctx: &Context, msg: &Message) {
        let content = &msg.content;
        
        // Command format: !addinfo @user <custom information>
        if content.starts_with("!addinfo") {
            if let Some(user_mention) = msg.mentions.first() {
                let user_id = user_mention.id.to_string();
                let user_name = &user_mention.name;
                
                // Extract the custom information (everything after the mention)
                if let Some(info_start) = content.find('>') {
                    let custom_info = content[info_start + 1..].trim().to_string();
                    if !custom_info.is_empty() {
                        // Store the custom information
                        {
                            let db_lock = self.db.lock().unwrap();
                            db_lock
                                .execute(
                                    "INSERT OR REPLACE INTO custom_user_info (user_id, info) VALUES (?1, ?2)",
                                    params![&user_id, &custom_info],
                                )
                                .expect("Failed to store custom user info");
                        }
                        
                        // Confirm the information was stored
                        if let Err(why) = msg.channel_id.say(&ctx.http, 
                            format!("Custom information about {} has been stored for future insults.", user_name)
                        ).await {
                            eprintln!("Error sending confirmation message: {:?}", why);
                        }
                    }
                }
            }
        }
        // Command format: !insult @user [custom prompt]
        else if content.starts_with("!insult") {
            if let Some(user_mention) = msg.mentions.first() {
                let user_id = user_mention.id.to_string();
                let user_name = &user_mention.name;
                
                // Extract custom prompt if provided
                let custom_prompt = if let Some(mention_end) = content.find('>') {
                    content[mention_end + 1..].trim().to_string()
                } else {
                    String::new()
                };
                
                // Get user data and custom info
                let (user_data, custom_info) = {
                    let db_lock = self.db.lock().unwrap();
                    
                    // Get message data
                    let data_opt: Option<String> = db_lock
                        .query_row(
                            "SELECT message_data FROM user_data WHERE user_id = ?1",
                            params![&user_id],
                            |row| row.get::<_, String>(0),
                        )
                        .optional()
                        .unwrap_or(None);
                    
                    // Get custom info
                    let info_opt: Option<String> = db_lock
                        .query_row(
                            "SELECT info FROM custom_user_info WHERE user_id = ?1",
                            params![&user_id],
                            |row| row.get::<_, String>(0),
                        )
                        .optional()
                        .unwrap_or(None);
                    
                    (data_opt.unwrap_or_default(), info_opt.unwrap_or_default())
                };
                
                // Generate the insult with custom prompt if provided
                match get_insult_with_custom_info(&self.config.openai_token, user_name, "", &"", &user_data, &custom_info, &custom_prompt).await {
                    Ok(insult) => {
                        // Send the insult to the insult channel and tag the user
                        let insult_channel_id = ChannelId::from(self.config.insult_channel_id.parse::<u64>().unwrap_or(0));
                        if let Err(why) = insult_channel_id.say(&ctx.http, 
                            format!("<@{}> {}", user_id, insult)
                        ).await {
                            eprintln!("Error sending insult: {:?}", why);
                            
                            // Notify admin that the insult failed
                            if let Err(why) = msg.channel_id.say(&ctx.http, 
                                format!("Failed to send insult to {}.", user_name)
                            ).await {
                                eprintln!("Error sending error message: {:?}", why);
                            }
                        } else {
                            // Confirm the insult was sent
                            if let Err(why) = msg.channel_id.say(&ctx.http, 
                                format!("Insult sent to {} in the insult channel.", user_name)
                            ).await {
                                eprintln!("Error sending confirmation message: {:?}", why);
                            }
                        }
                    },
                    Err(e) => {
                        eprintln!("Error generating insult: {}", e);
                        if let Err(why) = msg.channel_id.say(&ctx.http, 
                            format!("Failed to generate insult for {}: {}", user_name, e)
                        ).await {
                            eprintln!("Error sending error message: {:?}", why);
                        }
                    }
                }
            }
        }
        // Command format: !help
        else if content == "!help" {
            let help_message = "\
                **Admin Commands**\n\
                `!addinfo @user <custom information>` - Add custom information about a user for insults\n\
                `!insult @user [custom prompt]` - Generate and send an insult to the mentioned user in the insult channel\n\
                `!showinfo @user` - Show all stored information about a user\n\
                `!help` - Show this help message\
            ";
            
            if let Err(why) = msg.channel_id.say(&ctx.http, help_message).await {
                eprintln!("Error sending help message: {:?}", why);
            }
        }
        // Command format: !showinfo @user
        else if content.starts_with("!showinfo") {
            if let Some(user_mention) = msg.mentions.first() {
                let user_id = user_mention.id.to_string();
                let user_name = &user_mention.name;
                
                // Get all user data from database - use a block to ensure the lock is released before await
                let (message_data, history, custom_info) = {
                    let db_lock = self.db.lock().unwrap();
                    
                    // Get message data
                    let message_data: Option<String> = db_lock
                        .query_row(
                            "SELECT message_data FROM user_data WHERE user_id = ?1",
                            params![&user_id],
                            |row| row.get::<_, String>(0),
                        )
                        .optional()
                        .unwrap_or(None);
                    
                    // Get conversation history
                    let history: Option<String> = db_lock
                        .query_row(
                            "SELECT history FROM user_history WHERE user_id = ?1",
                            params![&user_id],
                            |row| row.get::<_, String>(0),
                        )
                        .optional()
                        .unwrap_or(None);
                    
                    // Get custom info
                    let custom_info: Option<String> = db_lock
                        .query_row(
                            "SELECT info FROM custom_user_info WHERE user_id = ?1",
                            params![&user_id],
                            |row| row.get::<_, String>(0),
                        )
                        .optional()
                        .unwrap_or(None);
                    
                    // Return the data and drop the lock
                    (message_data, history, custom_info)
                }; // db_lock is dropped here
                
                // Format and send the info
                let mut info_text = format!("Information about {}:\n\n", user_name);
                
                if let Some(info) = custom_info {
                    info_text.push_str(&format!("**Custom Info**:\n{}\n\n", info));
                } else {
                    info_text.push_str("**Custom Info**: None\n\n");
                }
                
                if let Some(hist) = history {
                    // Limit the amount of history shown to avoid Discord message limits
                    let truncated_hist = if hist.len() > 1000 {
                        format!("{} [...truncated...]", &hist[..1000])
                    } else {
                        hist
                    };
                    info_text.push_str(&format!("**Conversation History**:\n{}\n\n", truncated_hist));
                } else {
                    info_text.push_str("**Conversation History**: None\n\n");
                }
                
                if let Some(data) = message_data {
                    // Limit the amount of data shown to avoid Discord message limits
                    let truncated_data = if data.len() > 1500 {
                        format!("{} [...truncated...]", &data[..1500])
                    } else {
                        data
                    };
                    info_text.push_str(&format!("**Message Data**:\n{}", truncated_data));
                } else {
                    info_text.push_str("**Message Data**: None");
                }
                
                // Send the info
                if let Err(why) = msg.channel_id.say(&ctx.http, info_text).await {
                    eprintln!("Error sending user info: {:?}", why);
                }
            } else {
                if let Err(why) = msg.channel_id.say(&ctx.http, "Please mention a user: !showinfo @username").await {
                    eprintln!("Error sending error message: {:?}", why);
                }
            }
        }
    }

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
        // Check if this is an admin command in the admin channel
        if msg.channel_id.to_string() == self.config.admin_channel_id && !msg.author.bot {
            self.process_admin_command(&ctx, &msg).await;
            return;
        }
        
        // Store message data for all non-bot users regardless of channel
        if !msg.author.bot {
            let user_id_str = msg.author.id.to_string();
            let user_name = &msg.author.name;
            let user_text = &msg.content;
            
            // Only store non-empty messages
            if !user_text.is_empty() {
                // Get current timestamp
                let timestamp = chrono::Utc::now().timestamp();
                
                // Extract patterns and keywords from the message
                let mut tags = Vec::new();
                
                // Check for common patterns and keywords
                let content_lower = user_text.to_lowercase();
                
                // Check for common internet slang
                if content_lower.contains("lol") || content_lower.contains("lmao") || content_lower.contains("rofl") {
                    tags.push("#normie_humor");
                }
                
                // Check for excessive punctuation
                if user_text.contains("!!!") || user_text.contains("???") {
                    tags.push("#dramatic_typing");
                }
                
                // Check for message length patterns
                if user_text.len() < 10 {
                    tags.push("#low_effort_poster");
                } else if user_text.len() > 100 {
                    tags.push("#wall_of_text");
                }
                
                // Check for ALL CAPS
                if user_text.chars().filter(|c| c.is_uppercase()).count() > user_text.len() / 3 {
                    tags.push("#caps_shouter");
                }
                
                // Check for tryhard vocabulary
                if content_lower.contains("actually") || content_lower.contains("technically") {
                    tags.push("#well_actually");
                }
                
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
                    
                    // Add tags to the message
                    let tag_str = if !tags.is_empty() {
                        format!(" {}", tags.join(" "))
                    } else {
                        String::new()
                    };
                    
                    // Append new message and truncate if needed
                    let new_entry = format!("[{}] {}: {}{}", timestamp, user_name, user_text, tag_str);
                    
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
    
    // Add a table to store custom user information from admin commands
    conn.execute(
        "CREATE TABLE IF NOT EXISTS custom_user_info (
            user_id TEXT PRIMARY KEY,
            info TEXT NOT NULL
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

async fn get_insult_with_custom_info(openai_token: &str, username: &str, _user_text: &str, history: &str, user_data: &str, custom_info: &str, custom_prompt: &str) -> Result<String> {
    let mut messages = vec![
        serde_json::json!({ "role": "system", "content": "You are a mean, sarcastic asshole. Give short, blunt insults. NO flowery language. NO metaphors. NO Game of Thrones style. Just raw, direct savage burns. ONE OR TWO SENTENCES MAX. Be specific about their flaws. Never be poetic or philosophical, except when it allows you to be even more savage." }),
    ];

    if !history.is_empty() {
        messages.push(serde_json::json!({ "role": "system", "content": format!("Previous conversation: {}", history) }));
    }
    
    // Add user data if available
    if !user_data.is_empty() {
        messages.push(serde_json::json!({ "role": "system", "content": format!("User's message history: {}", user_data) }));
    }
    
    // Add custom information if available
    if !custom_info.is_empty() {
        messages.push(serde_json::json!({ "role": "system", "content": format!("Special info about user: {}", custom_info) }));
    }

    // Use custom prompt if provided, otherwise use default
    let prompt_content = if !custom_prompt.is_empty() {
        format!("I'm {}. {}", username, custom_prompt)
    } else {
        format!(" Roast {} based on the data you have. Be specific about my flaws from my message history. Keep it short and savage.", username)
    };
    
    messages.push(serde_json::json!({ "role": "user", "content": prompt_content }));

    let client = reqwest::Client::new();
    let res = client
        .post("https://api.openai.com/v1/chat/completions")
        .bearer_auth(openai_token)
        .json(&serde_json::json!({
            "model": "gpt-4o",
            "messages": messages,
            "max_tokens": 1000, // Significantly increased max_tokens for more detailed and longer insults
            "temperature": 1 // Slightly higher temperature for more creative/varied insults
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

async fn get_insult(openai_token: &str, username: &str, user_text: &str, history: &str, user_data: &str) -> Result<String> {
    let mut messages = vec![
        serde_json::json!({ "role": "system", "content": "You are a mean, sarcastic asshole. Give short, blunt insults. NO flowery language. NO metaphors. NO Game of Thrones style. Just raw, direct savage burns. ONE OR TWO SENTENCES MAX. Be specific about their flaws. Never be poetic or philosophical, except when it allows you to be even more savage." }),
    ];

    if !history.is_empty() {
        messages.push(serde_json::json!({ "role": "system", "content": format!("Previous conversation: {}", history) }));
    }
    
    // Add user data if available
    if !user_data.is_empty() {
        messages.push(serde_json::json!({ "role": "system", "content": format!("User's message history: {}", user_data) }));
    }

    messages.push(serde_json::json!({ "role": "user", "content": format!("I'm {}. My message: '{}'. Roast me based on this and my past messages. Use specific details from my history. Keep it short and savage.", username, user_text) }));

    let client = reqwest::Client::new();
    let res = client
        .post("https://api.openai.com/v1/chat/completions")
        .bearer_auth(openai_token)
        .json(&serde_json::json!({
            "model": "gpt-4o",
            "messages": messages,
            "max_tokens": 1000, // Significantly increased max_tokens for more detailed and longer insults
            "temperature": 1// Slightly higher temperature for more creative/varied insults
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
