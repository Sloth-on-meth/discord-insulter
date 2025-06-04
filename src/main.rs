use serenity::async_trait;
use serenity::model::channel::Message;
use serenity::model::gateway::Ready;
use serenity::model::id::{ChannelId, UserId};
use serenity::prelude::*;
use serde::Deserialize;
use std::fs;
use anyhow::Result;
use rusqlite::{params, Connection, OptionalExtension};
use reqwest;
use std::sync::{Arc, Mutex};
// Removed unused SystemTime import
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
        log_info("Processing admin command");
        let content = &msg.content;
        
        // Command format: !addinfo @user <custom information>
        if content.starts_with("!addinfo") {
            log_info("Received !addinfo command");
            if let Some(user_mention) = msg.mentions.first() {
                let user_id = user_mention.id.to_string();
                let user_name = &user_mention.name;
                
                log_info(&format!("Extracting custom information for user {}", user_name));
                // Extract the custom information (everything after the mention)
                if let Some(info_start) = content.find('>') {
                    let custom_info = content[info_start + 1..].trim().to_string();
                    if !custom_info.is_empty() {
                        // Store the custom information by appending to existing info
                        {
                            let db_lock = self.db.lock().unwrap();
                            
                            // First check if there's existing info
                            let existing_info: Option<String> = db_lock
                                .query_row(
                                    "SELECT info FROM custom_user_info WHERE user_id = ?1",
                                    [&user_id],
                                    |row| row.get::<_, String>(0),
                                )
                                .optional()
                                .unwrap_or(None);
                            
                            // Append new info to existing info or create new entry
                            let updated_info = match existing_info {
                                Some(existing) => format!("{} \n• {}", existing, custom_info),
                                None => custom_info.to_string(),
                            };
                            
                            // Update the database
                            db_lock
                                .execute(
                                    "INSERT OR REPLACE INTO custom_user_info (user_id, info) VALUES (?1, ?2)",
                                    [&user_id, &updated_info],
                                )
                                .expect("Failed to store custom user info");
                        }
                        
                        // Confirm the information was stored
                        if let Err(why) = msg.channel_id.say(&ctx.http, 
                            format!("New custom information about {} has been added to their profile for future insults.", user_name)
                        ).await {
                            eprintln!("Error sending confirmation message: {:?}", why);
                        }
                    }
                }
            }
        }
        // Command format: !insult @user [custom prompt]
        else if content.starts_with("!insult ") || content == "!insult" {
            log_info("Received !insult command");
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
                            params![user_id],
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
        // Command format: !clearinfo @user
        else if content.starts_with("!clearinfo") {
            log_info("Received !clearinfo command");
            if let Some(user_mention) = msg.mentions.first() {
                let user_id = user_mention.id.to_string();
                let user_name = &user_mention.name;
                
                // Clear custom info from database
                // Execute database operation before any await points
                let delete_result = {
                    let db_lock = self.db.lock().unwrap();
                    db_lock.execute(
                        "DELETE FROM custom_user_info WHERE user_id = ?1",
                        [&user_id],
                    )
                };
                
                // Process the result after the lock is dropped
                match delete_result {
                    Ok(_) => {
                        log_info(&format!("Cleared custom info for user ID: {}", user_id));
                        
                        // Prepare message text before await
                        let message_text = format!("Custom information about {} has been cleared.", user_name);
                        
                        // Confirm the information was cleared
                        if let Err(why) = msg.channel_id.say(&ctx.http, message_text).await {
                            log_error(&format!("Error sending confirmation message: {:?}", why));
                        }
                    },
                    Err(e) => {
                        log_error(&format!("Failed to clear custom info: {}", e));
                        
                        if let Err(why) = msg.channel_id.say(&ctx.http, 
                            format!("Failed to clear custom information for {}: {}", user_name, e)
                        ).await {
                            log_error(&format!("Error sending error message: {:?}", why));
                        }
                    }
                }
            } else {
                if let Err(why) = msg.channel_id.say(&ctx.http, "Please mention a user to clear their custom information.").await {
                    log_error(&format!("Error sending error message: {:?}", why));
                }
            }
        }
        // Command format: !readmessages [channel_id]
        else if content.starts_with("!readmessages") {
            log_info("Received !readmessages command");
            
            // Parse optional channel ID from command
            let target_channel_id = if content.len() > 13 { // "!readmessages ".len() = 13
                let channel_id_str = content[13..].trim();
                if !channel_id_str.is_empty() {
                    match channel_id_str.parse::<u64>() {
                        Ok(id) => Some(ChannelId::from(id)),
                        Err(_) => {
                            if let Err(why) = msg.channel_id.say(&ctx.http, "Invalid channel ID format. Using current channel.").await {
                                log_error(&format!("Error sending message: {:?}", why));
                            }
                            None
                        }
                    }
                } else {
                    None
                }
            } else {
                None
            };
            
            // Use specified channel or current channel
            let channel_to_read = target_channel_id.unwrap_or(msg.channel_id);
            
            // Send a status message
            if let Err(why) = msg.channel_id.say(&ctx.http, 
                format!("Starting to read the last 2000 messages from channel <#{}>. This may take a while...", channel_to_read)
            ).await {
                log_error(&format!("Error sending status message: {:?}", why));
            }
            
            // Fetch messages from the channel
            let messages = match channel_to_read.messages(&ctx.http, serenity::builder::GetMessages::default().limit(100)).await {
                Ok(msgs) => msgs,
                Err(e) => {
                    log_error(&format!("Failed to fetch messages: {}", e));
                    if let Err(why) = msg.channel_id.say(&ctx.http, 
                        format!("Failed to fetch messages: {}", e)
                    ).await {
                        log_error(&format!("Error sending error message: {:?}", why));
                    }
                    return;
                }
            };
            
            log_info(&format!("Retrieved {} messages from channel {}", messages.len(), channel_to_read));
            
            // Process messages and store in database
            let mut users_processed = 0;
            let mut messages_processed = 0;
            let mut new_users = 0;
            
            // Group messages by user
            let mut user_messages: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();
            
            // First pass: collect messages by user
            for message in &messages {
                if !message.author.bot {
                    let user_id = message.author.id.to_string();
                    let content = message.content.clone();
                    
                    if !content.is_empty() {
                        user_messages.entry(user_id)
                            .or_insert_with(Vec::new)
                            .push(content);
                        messages_processed += 1;
                    }
                }
            }
            
            // Second pass: update database for each user
            for (user_id, contents) in user_messages {
                // Combine all messages for this user
                let combined_content = contents.join("\n");
                
                // Update the database
                let update_result = {
                    let db_lock = self.db.lock().unwrap();
                    
                    // Check if user exists
                    let user_exists = db_lock
                        .query_row(
                            "SELECT 1 FROM user_data WHERE user_id = ?1",
                            [&user_id],
                            |_| Ok(true)
                        )
                        .optional()
                        .unwrap_or(None)
                        .is_some();
                    
                    if user_exists {
                        // Get existing message data
                        let existing_data: Option<String> = db_lock
                            .query_row(
                                "SELECT message_data FROM user_data WHERE user_id = ?1",
                                [&user_id],
                                |row| row.get::<_, String>(0)
                            )
                            .optional()
                            .unwrap_or(None);
                        
                        // Append new data to existing data
                        let updated_data = match existing_data {
                            Some(existing) => format!("{} {}", existing, combined_content),
                            None => combined_content.clone()
                        };
                        
                        // Update the database
                        db_lock.execute(
                            "UPDATE user_data SET message_data = ?1 WHERE user_id = ?2",
                            [&updated_data, &user_id]
                        )
                    } else {
                        // Insert new user
                        new_users += 1;
                        db_lock.execute(
                            "INSERT INTO user_data (user_id, message_data, last_updated) VALUES (?1, ?2, ?3)",
                            params![&user_id, &combined_content, &(chrono::Utc::now().timestamp())]
                        )
                    }
                };
                
                // Check result
                if let Err(e) = update_result {
                    log_error(&format!("Failed to update database for user {}: {}", user_id, e));
                } else {
                    users_processed += 1;
                }
            }
            
            // Send completion message
            if let Err(why) = msg.channel_id.say(&ctx.http, 
                format!("Message reading complete! Processed {} messages from {} users ({} new users added to database).", 
                    messages_processed, users_processed, new_users)
            ).await {
                log_error(&format!("Error sending completion message: {:?}", why));
            }
        }
        // Command format: !help
        else if content == "!help" {
            log_info("Received !help command");
            let help_message = "\
                **Admin Commands**\n\
                `!addinfo @user <custom information>` - Add custom information about a user for insults\n\
                `!clearinfo @user` - Clear all custom information about a user\n\
                `!insult @user [custom prompt]` - Generate and send an insult to the mentioned user in the insult channel\n\
                `!insultall` - Generate insults for all users in the database\n\
                `!showinfo @user` - Show all stored information about a user\n\
                `!readmessages [channel_id]` - Read the last 2000 messages from the server or specified channel and store them in the database\n\
                `!help` - Show this help message\
            ";
            
            if let Err(why) = msg.channel_id.say(&ctx.http, help_message).await {
                eprintln!("Error sending help message: {:?}", why);
            }
        }
        // Command format: !showinfo @user
        else if content.starts_with("!showinfo") {
            log_info("Received !showinfo command");
            if let Some(user_mention) = msg.mentions.first() {
                let user_id = user_mention.id.to_string();
                let user_name = &user_mention.name;
                
                // Get message data
                let message_data: Option<String> = {
                    let db_lock = self.db.lock().unwrap();
                    let result = db_lock
                        .query_row(
                            "SELECT message_data FROM user_data WHERE user_id = ?1",
                            [&user_id],
                            |row| row.get::<_, String>(0),
                        )
                        .optional()
                        .unwrap_or(None);
                    result
                };
                
                // Get conversation history
                let history: Option<String> = {
                    let db_lock = self.db.lock().unwrap();
                    let result = db_lock
                        .query_row(
                            "SELECT history FROM user_history WHERE user_id = ?1",
                            [&user_id],
                            |row| row.get::<_, String>(0),
                        )
                        .optional()
                        .unwrap_or(None);
                    result
                };
                
                // Get custom info
                let custom_info: Option<String> = {
                    let db_lock = self.db.lock().unwrap();
                    let result = db_lock
                        .query_row(
                            "SELECT info FROM custom_user_info WHERE user_id = ?1",
                            [&user_id],
                            |row| row.get::<_, String>(0),
                        )
                        .optional()
                        .unwrap_or(None);
                    result
                };
                
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
        // Command format: !insultall
        else if content == "!insultall" {
            log_info("Received !insultall command");
            
            // Get the insult channel ID
            let insult_channel_id = ChannelId::from(self.config.insult_channel_id.parse::<u64>().unwrap_or(0));
            
            // Get all user IDs from the database - simplified approach
            let mut user_ids: Vec<String> = Vec::new();
            log_info("Fetching all user IDs from database");
            
            // Use a simpler approach to avoid borrow issues
            {
                let db_lock = self.db.lock().unwrap();
                
                // Use a direct query instead of prepare/execute pattern
                let stmt_text = "SELECT DISTINCT user_id FROM user_data";
                let mut stmt = db_lock.prepare_cached(stmt_text).unwrap();
                
                // Execute the query and collect results
                let rows = stmt.query_map([], |row| row.get::<_, String>(0)).unwrap();
                
                // Process the results
                for id_result in rows {
                    if let Ok(id) = id_result {
                        log_info(&format!("Found user ID: {}", id));
                        user_ids.push(id);
                    }
                }
            } // db_lock is dropped here
            
            // Inform the admin that insults are being generated
            let count = user_ids.len();
            log_info(&format!("Found {} users in database", count));
            
            if count == 0 {
                log_info("No users found in database, aborting !insultall");
                if let Err(why) = msg.channel_id.say(&ctx.http, "No users found in the database.").await {
                    eprintln!("Error sending message: {:?}", why);
                }
                return;
            }
            
            if let Err(why) = msg.channel_id.say(&ctx.http, 
                format!("Generating insults for {} users. This may take some time...", count)
            ).await {
                eprintln!("Error sending message: {:?}", why);
            }
            
            // Process each user one at a time
            for (index, user_id) in user_ids.iter().enumerate() {
                let user_id = user_id.clone(); // Clone the string to avoid borrowing issues
                log_info(&format!("Processing user {}/{}: ID {}", index + 1, count, user_id));
                
                // Try to get username from Discord API
                let user_id_u64 = match user_id.parse::<u64>() {
                    Ok(id) => id,
                    Err(_) => {
                        log_error(&format!("Failed to parse user ID: {}", user_id));
                        continue; // Skip this user
                    }
                };
                
                // Get user data from database
                log_info(&format!("Fetching data for user ID: {}", user_id));
                
                // Get message data - execute database query before any await points
                let user_data = {
                    let db_lock = self.db.lock().unwrap();
                    let result = db_lock.query_row(
                        "SELECT message_data FROM user_data WHERE user_id = ?1",
                        &[&user_id as &dyn rusqlite::ToSql],
                        |row| row.get::<_, String>(0)
                    );
                    match result {
                        Ok(data) => data,
                        Err(_) => String::new()
                    }
                };
                
                // Get conversation history
                let history = {
                    let db_lock = self.db.lock().unwrap();
                    match db_lock.query_row(
                        "SELECT history FROM user_history WHERE user_id = ?1",
                        params![&user_id],
                        |row| row.get::<_, String>(0)
                    ) {
                        Ok(history) => history,
                        Err(_) => String::new()
                    }
                };
                
                // Get custom info
                let custom_info = {
                    let db_lock = self.db.lock().unwrap();
                    match db_lock.query_row(
                        "SELECT info FROM custom_user_info WHERE user_id = ?1",
                        params![&user_id],
                        |row| row.get::<_, String>(0)
                    ) {
                        Ok(info) => info,
                        Err(_) => String::new()
                    }
                };
                
                // Try to get username from Discord API
                log_info(&format!("Fetching username for user ID: {}", user_id));
                let username = match UserId::from(user_id_u64).to_user(&ctx.http).await {
                    Ok(user) => user.name,
                    Err(_) => format!("User {}", user_id)
                };
                
                log_info(&format!("Got username: {} for user ID: {}", username, user_id));
                
                // Send a status message to admin channel
                if let Err(why) = msg.channel_id.say(&ctx.http, 
                    format!("Generating insult for {}...", username)
                ).await {
                    eprintln!("Error sending status message: {:?}", why);
                }
                
                // Generate the insult
                log_info(&format!("Generating insult for user: {}", username));
                match get_insult_with_custom_info(
                    &self.config.openai_token, 
                    &username, 
                    "", 
                    &history, 
                    &user_data, 
                    &custom_info, 
                    ""
                ).await {
                    Ok(insult) => {
                        // Send the insult to the insult channel and tag the user
                        if let Err(why) = insult_channel_id.say(&ctx.http, 
                            format!("<@{}> {}", user_id, insult)
                        ).await {
                            eprintln!("Error sending insult: {:?}", why);
                            if let Err(why2) = msg.channel_id.say(&ctx.http, 
                                format!("Failed to send insult to {}: {:?}", username, why)
                            ).await {
                                eprintln!("Error sending error message: {:?}", why2);
                            }
                        } else {
                            if let Err(why) = msg.channel_id.say(&ctx.http, 
                                format!("Insult sent to {}.", username)
                            ).await {
                                eprintln!("Error sending confirmation message: {:?}", why);
                            }
                        }
                        
                        // Add a small delay to avoid rate limiting
                        log_info("Adding delay to avoid rate limiting");
                        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                    },
                    Err(e) => {
                        log_error(&format!("Error generating insult for {}: {}", username, e));
                        if let Err(why) = msg.channel_id.say(&ctx.http, 
                            format!("Failed to generate insult for {}: {}", username, e)
                        ).await {
                            eprintln!("Error sending error message: {:?}", why);
                        }
                    }
                }
            }
            
            // Inform the admin that all insults have been sent
            log_info(&format!("Finished sending insults to all {} users", count));
            if let Err(why) = msg.channel_id.say(&ctx.http, 
                format!("Finished sending insults to {} users.", count)
            ).await {
                eprintln!("Error sending message: {:?}", why);
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

// Helper function for logging with timestamp
fn log_info(message: &str) {
    let now = chrono::Local::now();
    println!("[{}] INFO: {}", now.format("%Y-%m-%d %H:%M:%S"), message);
}

fn log_error(message: &str) {
    let now = chrono::Local::now();
    eprintln!("[{}] ERROR: {}", now.format("%Y-%m-%d %H:%M:%S"), message);
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
                            [&user_id_str],
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
        log_info(&format!("{} is connected!", ready.user.name));
        log_info("Bot is ready to receive commands");
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
        serde_json::json!({ "role": "system", "content": "You are a witty, sarcastic comedian doing a roast. Give humorous insults that are funny rather than cruel. Use clever wordplay, puns, and playful teasing. ONE OR TWO SENTENCES MAX. but keep it light-hearted enough that the person being roasted would laugh too. Think Comedy Central Roast style but toned down a bit." }),
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
        format!("Roast {} based on the data you have. you can use their quirks from their message history. Keep it funny and clever.", username)
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

    messages.push(serde_json::json!({ "role": "user", "content": format!("I'm {}. My message: '{}'. Roast me based on this and my past messages and custom info Keep it short and savage.", username, user_text) }));

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
