use serenity::async_trait;
use serenity::model::channel::Message;
use serenity::model::gateway::Ready;
use serenity::model::id::{ChannelId, UserId};
use serenity::prelude::*;
use serde::Deserialize;
use std::fs;
use anyhow::Result;
mod convo_utils;
mod summarize;
use convo_utils::{random_chance, random_argument_hook};
use summarize::summarize_history;
use rusqlite::{params, Connection, OptionalExtension};
use reqwest;
use std::sync::{Arc, Mutex};
// Removed unused SystemTime import
// Removed unused HashMap import

const MAX_HISTORY_CHARS: usize = 2000; // Max characters for conversation history
const MAX_USER_DATA_CHARS: usize = 5000; // Max characters for user data collection

// Humor categories for themed insults
const HUMOR_CATEGORIES: [&str; 6] = [
    "roast",           // Standard roast comedy
    "dad_joke",        // Corny dad joke style insults
    "shakespeare",     // Elizabethan-style insults
    "sci_fi",          // Sci-fi themed insults
    "surreal",         // Absurdist/surreal humor
    "celebrity",       // Celebrity roast style
];


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
                let custom_prompt = if let Some(mention_end) = content.find('>'){
                    content[mention_end + 1..].trim().to_string()
                } else {
                    String::new()
                };
                
                // Get user data and custom info
                // Get user data, summary, and custom info for the mentioned user
                let (user_data, summary, custom_info) = {
                    let db_lock = self.db.lock().unwrap();
                    let mut data = String::new();
                    let mut summary = String::new();
                    let mut info = String::new();
                    let _ = db_lock.query_row(
                        "SELECT message_data, summary FROM user_data WHERE user_id = ?1",
                        params![&user_id],
                        |row| {
                            data = row.get::<_, String>(0)?;
                            summary = row.get::<_, String>(1)?;
                            Ok(())
                        }
                    );
                    let _ = db_lock.query_row(
                        "SELECT info FROM custom_user_info WHERE user_id = ?1",
                        params![&user_id],
                        |row| {
                            info = row.get::<_, String>(0)?;
                            Ok(())
                        }
                    );
                    (data, summary, info)
                };

                
                // Check if this is a themed insult request
                if custom_prompt.starts_with("theme:") || custom_prompt.starts_with("style:") {
                    let theme = custom_prompt.split(':').nth(1).unwrap_or("roast").trim().to_lowercase();
                    
                    // Generate the themed insult
                    match get_themed_insult(&self.config.openai_token, user_name, "", &"", &user_data, &theme).await {
                        Ok(insult) => {
                            // Send the insult to the insult channel and tag the user
                            let insult_channel_id = ChannelId::from(self.config.insult_channel_id.parse::<u64>().unwrap_or(0));
                            if let Err(why) = insult_channel_id.say(&ctx.http, 
                                format!("<@{}> {}", user_id, insult)
                            ).await {
                                eprintln!("Error sending insult: {:?}", why);
                                
                                // Notify admin that the insult failed
                                if let Err(why) = msg.channel_id.say(&ctx.http, 
                                    format!("Failed to send themed insult to {}.", user_name)
                                ).await {
                                    eprintln!("Error sending error message: {:?}", why);
                                }
                            } else {
                                // Confirm the insult was sent
                                if let Err(why) = msg.channel_id.say(&ctx.http, 
                                    format!("Themed insult sent to {} in the insult channel.", user_name)
                                ).await {
                                    eprintln!("Error sending confirmation message: {:?}", why);
                                }
                            }
                        },
                        Err(e) => {
                            eprintln!("Error generating themed insult: {}", e);
                            if let Err(why) = msg.channel_id.say(&ctx.http, 
                                format!("Failed to generate themed insult for {}: {}", user_name, e)
                            ).await {
                                eprintln!("Error sending error message: {:?}", why);
                            }
                        }
                    }
                } else {
                    // Generate the regular insult with custom prompt if provided
                    match get_insult_with_custom_info(&self.config.openai_token, user_name, "", &"", &user_data, &summary, &custom_info, &custom_prompt, &msg.author.name).await {
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
        }
        // Command format: !nicemessage @user [custom prompt]
        else if content.starts_with("!nicemessage ") || content == "!nicemessage" {
            log_info("Received !nicemessage command");
            if let Some(user_mention) = msg.mentions.first() {
                let user_id = user_mention.id.to_string();
                let user_name = &user_mention.name;
                
                // Extract custom prompt if provided
                let custom_prompt = if let Some(mention_end) = content.find('>'){
                    content[mention_end + 1..].trim().to_string()
                } else {
                    String::new()
                };
                
                // Get user data and custom info
                // Get user data, summary, and custom info for the mentioned user
                let (user_data, summary, custom_info) = {
                    let db_lock = self.db.lock().unwrap();
                    let mut data = String::new();
                    let mut summary = String::new();
                    let mut info = String::new();
                    let _ = db_lock.query_row(
                        "SELECT message_data, summary FROM user_data WHERE user_id = ?1",
                        params![&user_id],
                        |row| {
                            data = row.get::<_, String>(0)?;
                            summary = row.get::<_, String>(1)?;
                            Ok(())
                        }
                    );
                    let _ = db_lock.query_row(
                        "SELECT info FROM custom_user_info WHERE user_id = ?1",
                        params![&user_id],
                        |row| {
                            info = row.get::<_, String>(0)?;
                            Ok(())
                        }
                    );
                    (data, summary, info)
                };

                
                // Generate the nice message with custom prompt if provided
                match get_nice_message_with_custom_info(&self.config.openai_token, user_name, "", &"", &user_data, &custom_info, &custom_prompt).await {
                    Ok(nice_message) => {
                        // Send the nice message to the insult channel and tag the user
                        let insult_channel_id = ChannelId::from(self.config.insult_channel_id.parse::<u64>().unwrap_or(0));
                        if let Err(why) = insult_channel_id.say(&ctx.http, 
                            format!("<@{}> {}", user_id, nice_message)
                        ).await {
                            log_error(&format!("Error sending nice message: {:?}", why));
                            
                            // Notify admin that the nice message failed
                            if let Err(why) = msg.channel_id.say(&ctx.http, 
                                format!("Failed to send nice message to {}.", user_name)
                            ).await {
                                log_error(&format!("Error sending error message: {:?}", why));
                            }
                        } else {
                            // Confirm the nice message was sent
                            if let Err(why) = msg.channel_id.say(&ctx.http, 
                                format!("Nice message sent to {} in the insult channel.", user_name)
                            ).await {
                                log_error(&format!("Error sending confirmation message: {:?}", why));
                            }
                        }
                    },
                    Err(e) => {
                        log_error(&format!("Error generating nice message: {}", e));
                        if let Err(why) = msg.channel_id.say(&ctx.http, 
                            format!("Failed to generate nice message for {}: {}", user_name, e)
                        ).await {
                            log_error(&format!("Error sending error message: {:?}", why));
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
        // Command format: !readmessages
        else if content.starts_with("!readmessages") {
            log_info("Received !readmessages command");
            
            // Send a status message
            if let Err(why) = msg.channel_id.say(&ctx.http, 
                "Starting to read all messages from all channels, 100 at a time. This may take a while..."
            ).await {
                log_error(&format!("Error sending status message: {:?}", why));
            }
            
            // Get all channels in the guild
            let guild_id = match msg.guild_id {
                Some(id) => id,
                None => {
                    if let Err(why) = msg.channel_id.say(&ctx.http, "This command must be used in a server.").await {
                        log_error(&format!("Error sending message: {:?}", why));
                    }
                    return;
                }
            };
            
            let channels = match guild_id.channels(&ctx.http).await {
                Ok(channels) => channels,
                Err(e) => {
                    log_error(&format!("Failed to fetch channels: {}", e));
                    if let Err(why) = msg.channel_id.say(&ctx.http, 
                        format!("Failed to fetch channels: {}", e)
                    ).await {
                        log_error(&format!("Error sending error message: {:?}", why));
                    }
                    return;
                }
            };
            
            // Collect all messages from all channels
            let mut all_messages = Vec::new();
            let mut channels_processed = 0;
            let mut channels_failed = 0;
            
            for (channel_id, _) in channels {
                // Only process text channels
                match channel_id.to_channel(&ctx.http).await {
                    Ok(channel) => {
                        // Check if this is a text channel
                        match channel {
                            serenity::model::channel::Channel::Guild(guild_channel) => {
                                if !guild_channel.is_text_based() {
                                    continue;
                                }
                            },
                            // Skip non-guild channels or non-text channels
                            _ => continue,
                        }
                    },
                    Err(_) => continue,
                }
                
                // Fetch all messages from the channel, 100 at a time
                let mut channel_messages = Vec::new();
                let mut last_message_id = None;
                let mut total_channel_messages = 0;
                
                // Keep fetching messages until we've got them all
                loop {
                    let mut message_builder = serenity::builder::GetMessages::default().limit(100);
                    
                    // If we have a last message ID, use it to fetch older messages
                    if let Some(id) = last_message_id {
                        message_builder = message_builder.before(id);
                    }
                    
                    match channel_id.messages(&ctx.http, message_builder).await {
                        Ok(msgs) => {
                            let batch_size = msgs.len();
                            total_channel_messages += batch_size;
                            
                            // If we got messages, update the last message ID for pagination
                            if !msgs.is_empty() {
                                last_message_id = Some(msgs.last().unwrap().id);
                                channel_messages.extend(msgs);
                            }
                            
                            // If we got fewer than 100 messages, we've reached the end
                            if batch_size < 100 {
                                break;
                            }
                            
                            // Add a small delay to avoid rate limiting
                            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                        },
                        Err(e) => {
                            log_error(&format!("Failed to fetch messages from channel {}: {}", channel_id, e));
                            break;
                        }
                    }
                }
                
                if !channel_messages.is_empty() {
                    log_info(&format!("Retrieved {} messages from channel {}", total_channel_messages, channel_id));
                    all_messages.extend(channel_messages);
                    channels_processed += 1;
                } else {
                    log_info(&format!("No messages found in channel {}", channel_id));
                    channels_failed += 1;
                }
            }
            
            log_info(&format!("Retrieved a total of {} messages from {} channels ({} failed)", 
                all_messages.len(), channels_processed, channels_failed));
            
            // Use the collected messages for processing
            let messages = all_messages;
            
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
                        
                        // Process new data to avoid repetition
                        let updated_data = match existing_data {
                            Some(existing) => {
                                // Split existing data into words/phrases for deduplication
                                let existing_words: std::collections::HashSet<String> = 
                                    existing.split_whitespace()
                                    .map(|s| s.to_lowercase())
                                    .collect();
                                
                                // Filter out repetitive content
                                let new_content: Vec<String> = combined_content
                                    .split_whitespace()
                                    .filter(|word| {
                                        let lower = word.to_lowercase();
                                        !existing_words.contains(&lower) || 
                                        // Keep some common words that might be important in context
                                        word.len() <= 3 || 
                                        // Random sampling to keep some duplicates for context
                                        rand::random::<f32>() < 0.2
                                    })
                                    .map(|s| s.to_string())
                                    .collect();
                                
                                // If we have new content after filtering, append it
                                if !new_content.is_empty() {
                                    format!("{} {}", existing, new_content.join(" "))
                                } else {
                                    existing
                                }
                            },
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
                `!nicemessage @user [custom prompt]` - Generate and send a nice, positive message to the mentioned user\n\
                `!insultall` - Generate insults for all users in the database\n\
                `!showinfo @user` - Show all stored information about a user\n\
                `!readmessages` - Read all messages from all channels (100 at a time) and store them in the database\n\
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
                
                // Format and send the info with stricter limits to avoid MessageTooLong errors
                let mut info_text = format!("Information about {}:\n\n", user_name);
                
                // Discord has a 2000 character limit, so we need to be careful about the total length
                // Reserve space for headers and formatting (about 200 characters)
                const MAX_TOTAL_LENGTH: usize = 1800;
                const MAX_CUSTOM_INFO: usize = 300;
                const MAX_HISTORY: usize = 500;
                const MAX_MESSAGE_DATA: usize = 800;
                
                // Add custom info with stricter limits
                if let Some(info) = custom_info {
                    let truncated_info = if info.len() > MAX_CUSTOM_INFO {
                        format!("{} [...truncated...]", &info[..MAX_CUSTOM_INFO])
                    } else {
                        info
                    };
                    info_text.push_str(&format!("**Custom Info**:\n{}\n\n", truncated_info));
                } else {
                    info_text.push_str("**Custom Info**: None\n\n");
                }
                
                // Add conversation history with stricter limits
                if let Some(hist) = history {
                    let truncated_hist = if hist.len() > MAX_HISTORY {
                        format!("{} [...truncated...]", &hist[..MAX_HISTORY])
                    } else {
                        hist
                    };
                    info_text.push_str(&format!("**Conversation History**:\n{}\n\n", truncated_hist));
                } else {
                    info_text.push_str("**Conversation History**: None\n\n");
                }
                
                // Add message data with stricter limits
                if let Some(data) = message_data {
                    let truncated_data = if data.len() > MAX_MESSAGE_DATA {
                        format!("{} [...truncated...]", &data[..MAX_MESSAGE_DATA])
                    } else {
                        data
                    };
                    info_text.push_str(&format!("**Message Data**:\n{}", truncated_data));
                } else {
                    info_text.push_str("**Message Data**: None");
                }
                
                // Final check to ensure we're under Discord's limit
                if info_text.len() > 2000 {
                    info_text = format!(
                        "Information about {}:\n\nWarning: Too much data to display completely. Showing truncated information.\n\n{}", 
                        user_name,
                        &info_text[..1900]
                    );
                }
                
                // Send the info
                if let Err(why) = msg.channel_id.say(&ctx.http, info_text).await {
                    log_error(&format!("Error sending user info: {:?}", why));
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
                    "", 
                    &custom_info, 
                    "", 
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
    let mut history = current_history.to_string();
    
    // Add new exchange
    let new_exchange = format!("\nUser: {}\nBot: {}", user_message, ai_response);
    history.push_str(&new_exchange);
    
    // Truncate if too long
    if history.len() > MAX_HISTORY_CHARS {
        // Find first newline after excess
        let excess = history.len() - MAX_HISTORY_CHARS;
        if let Some(pos) = history[excess..].find('\n') {
            history = history[(excess + pos + 1)..].to_string();
        } else {
            history = history[excess..].to_string();
        }
    }
    
    history
}

// Extract memorable elements from previous insults for callbacks
fn extract_callback_material(history: &str) -> Vec<String> {
    let mut callbacks = Vec::new();
    
    // Look for bot responses in the history
    for line in history.lines() {
        if line.starts_with("Bot: ") {
            let insult = &line[5..]; // Skip "Bot: "
            
            // Extract key phrases that might be good for callbacks
            // Look for phrases with strong imagery or distinctive words
            let key_phrases = extract_key_phrases(insult);
            callbacks.extend(key_phrases);
        }
    }
    
    // Limit to the 3 most recent callbacks
    if callbacks.len() > 3 {
        callbacks = callbacks[callbacks.len() - 3..].to_vec();
    }
    
    callbacks
}

// Extract key phrases from an insult that might be good for callbacks
fn extract_key_phrases(insult: &str) -> Vec<String> {
    let mut phrases = Vec::new();
    
    // Simple extraction based on punctuation and sentence structure
    // In a real implementation, this would be more sophisticated
    let mut current_phrase = String::new();
    let mut word_count = 0;
    
    for word in insult.split_whitespace() {
        current_phrase.push_str(word);
        current_phrase.push(' ');
        word_count += 1;
        
        // If we have 3-5 words or hit punctuation, consider it a phrase
        if word_count >= 3 && (word_count >= 5 || word.ends_with('.') || word.ends_with(',') || 
                               word.ends_with('!') || word.ends_with('?')) {
            // Clean up the phrase
            let clean_phrase = current_phrase.trim()
                .trim_end_matches(|c| c == '.' || c == ',' || c == '!' || c == '?')
                .to_string();
            
            // Only add meaningful phrases (with at least one non-common word)
            if is_meaningful_phrase(&clean_phrase) {
                phrases.push(clean_phrase);
            }
            
            // Reset for next phrase
            current_phrase.clear();
            word_count = 0;
        }
    }
    
    // Add any remaining phrase if it's meaningful
    let final_phrase = current_phrase.trim().to_string();
    if !final_phrase.is_empty() && is_meaningful_phrase(&final_phrase) {
        phrases.push(final_phrase);
    }
    
    phrases
}

// Check if a phrase is meaningful enough for a callback
fn is_meaningful_phrase(phrase: &str) -> bool {
    // Skip very short phrases
    if phrase.split_whitespace().count() < 3 {
        return false;
    }
    
    // Skip phrases that are just common words
    let common_words = ["the", "a", "an", "and", "or", "but", "if", "then", "so", "because", 
                       "when", "where", "how", "what", "why", "who", "which", "you", "your", "are", 
                       "is", "am", "was", "were", "be", "been", "have", "has", "had"];
    
    let mut has_uncommon_word = false;
    for word in phrase.split_whitespace() {
        let word_lower = word.to_lowercase();
        if !common_words.contains(&word_lower.as_str()) {
            has_uncommon_word = true;
            break;
        }
    }
    
    has_uncommon_word
}

// Helper function for logging with timestamp
fn log_info(message: &str) {
    let now = chrono::Local::now();
    println!("[{}] INFO: {}", now.format("%Y-%m-%d %H:%M:%S"), message);
}

// Random insult generator that doesn't use OpenAI API
fn get_random_insult(username: &str) -> String {
    use rand::seq::SliceRandom;
    
    let templates = [
        "[NAME] has the charisma of a wet paper towel and half the absorption capacity.",
        "If [NAME] were any more basic, they'd neutralize stomach acid.",
        "[NAME] is living proof that evolution can go in reverse.",
        "[NAME]'s brain runs on Internet Explorer... from 2003.",
        "I'd roast [NAME], but my mom taught me not to burn trash.",
        "[NAME] is about as useful as a screen door on a submarine.",
        "[NAME] is the human equivalent of a participation trophy.",
        "[NAME] is so dense, light bends around them.",
        "[NAME] has the personality of a Discord loading screen.",
        "[NAME] is the reason shampoo has instructions.",
        "[NAME] is as deep as a puddle in the Sahara.",
        "[NAME] has a face for radio and a voice for silent films.",
        "[NAME]'s personality is like unseasoned chicken - bland and disappointing.",
        "[NAME] is so slow, they'd lose a race with a loading bar.",
        "[NAME] is the human equivalent of a 'Reply All' email disaster.",
    ];
    
    let mut rng = rand::thread_rng();
    let template = templates.choose(&mut rng).unwrap_or(&templates[0]);
    template.replace("[NAME]", username)
}

fn log_error(message: &str) {
    let now = chrono::Local::now();
    eprintln!("[{}] ERROR: {}", now.format("%Y-%m-%d %H:%M:%S"), message);
}

// Debug function to log API request contents
fn log_api_request(messages: &Vec<serde_json::Value>) {
    let now = chrono::Local::now();
    eprintln!("[{}] API REQUEST PAYLOAD:", now.format("%Y-%m-%d %H:%M:%S"));
    for (i, msg) in messages.iter().enumerate() {
        if let Some(role) = msg.get("role").and_then(|r| r.as_str()) {
            if let Some(content) = msg.get("content").and_then(|c| c.as_str()) {
                let truncated = if content.len() > 100 {
                    format!("{:.100}... [total: {} chars]", content, content.len())
                } else {
                    content.to_string()
                };
                eprintln!("  [{}] {}: {}", i, role, truncated);
            }
        }
    }
    eprintln!("[{}] END API REQUEST PAYLOAD", now.format("%Y-%m-%d %H:%M:%S"));
}

// Extract behavior tags from user data
fn extract_tags_from_user_data(user_data: &str) -> Vec<String> {
    let mut tags = Vec::new();
    
    // Look for hashtags in the user data
    for line in user_data.lines() {
        let mut line_tags: Vec<String> = line.split_whitespace()
            .filter(|word| word.starts_with('#'))
            .map(|tag| tag.to_string())
            .collect();
        tags.append(&mut line_tags);
    }
    
    // Count occurrences of each tag
    let mut tag_counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for tag in tags {
        *tag_counts.entry(tag).or_insert(0) += 1;
    }
    
    // Only keep tags that appear at least twice (showing a pattern)
    let frequent_tags: Vec<String> = tag_counts.iter()
        .filter(|(_, &count)| count >= 2)
        .map(|(tag, _)| tag.replace("#", ""))
        .collect();
    
    frequent_tags
}

// Extract topics the user frequently discusses
fn extract_topics_from_user_data(user_data: &str) -> Vec<String> {
    // Common topics to look for
    let topic_keywords = [
        ("gaming", vec!["game", "gaming", "play", "played", "player", "steam", "xbox", "playstation", "nintendo"]),
        ("tech", vec!["code", "programming", "computer", "tech", "software", "developer", "app"]),
        ("anime", vec!["anime", "manga", "waifu", "japan", "weeb", "otaku"]),
        ("music", vec!["music", "song", "band", "album", "concert", "playlist"]),
        ("movies", vec!["movie", "film", "cinema", "watch", "netflix", "series", "show"]),
        ("food", vec!["food", "eat", "restaurant", "cooking", "recipe", "meal"]),
        ("sports", vec!["sports", "team", "football", "basketball", "soccer", "game", "match"]),
        ("politics", vec!["politics", "political", "government", "election", "vote"]),
        ("crypto", vec!["crypto", "bitcoin", "ethereum", "nft", "blockchain", "token"]),
        ("memes", vec!["meme", "dank", "sus", "amogus", "poggers", "based"])
    ];
    
    let user_data_lower = user_data.to_lowercase();
    
    // Count occurrences of each topic in the user data
    let mut topic_counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    
    for (topic, keywords) in topic_keywords.iter() {
        let count = keywords.iter()
            .map(|keyword| {
                user_data_lower.matches(keyword).count()
            })
            .sum();
        
        if count > 0 {
            topic_counts.insert(topic, count);
        }
    }
    
    // Sort topics by frequency and take the top 3
    let mut topics: Vec<(&str, usize)> = topic_counts.into_iter().collect();
    topics.sort_by(|a, b| b.1.cmp(&a.1));
    
    topics.iter()
        .take(3)
        .map(|(topic, _)| topic.to_string())
        .collect()
}

// Analyze the current message for context
fn analyze_current_message(message: &str) -> String {
    if message.is_empty() {
        return String::new();
    }
    
    let message_lower = message.to_lowercase();
    let mut contexts = Vec::new();
    
    // Check message tone
    if message.contains('!') {
        contexts.push("excited");
    }
    if message.contains('?') {
        contexts.push("asking questions");
    }
    if message.len() > 100 {
        contexts.push("being long-winded");
    }
    if message.len() < 10 {
        contexts.push("being terse");
    }
    
    // Check for specific content
    if message_lower.contains("help") || message_lower.contains("how do i") {
        contexts.push("asking for help");
    }
    if message_lower.contains("i think") || message_lower.contains("in my opinion") {
        contexts.push("sharing their opinion");
    }
    if message.chars().filter(|c| c.is_uppercase()).count() > message.len() / 3 {
        contexts.push("SHOUTING IN ALL CAPS");
    }
    if message_lower.contains("lol") || message_lower.contains("haha") || message_lower.contains("lmao") {
        contexts.push("trying to be funny");
    }
    
    // Join contexts with commas
    contexts.join(", ")
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
                
                // More detailed personality analysis
                
                // Communication style
                if content_lower.contains("lol") || content_lower.contains("lmao") || content_lower.contains("rofl") {
                    tags.push("#normie_humor");
                }
                if content_lower.contains("uwu") || content_lower.contains(":3") || content_lower.contains("nya") {
                    tags.push("#uwu_speak");
                }
                if user_text.contains("!!!") || user_text.contains("???") {
                    tags.push("#dramatic_typing");
                }
                if user_text.chars().filter(|c| c.is_uppercase()).count() > user_text.len() / 3 {
                    tags.push("#caps_shouter");
                }
                
                // Message patterns
                if user_text.len() < 10 {
                    tags.push("#low_effort_poster");
                } else if user_text.len() > 100 {
                    tags.push("#wall_of_text");
                }
                
                // Personality indicators
                if content_lower.contains("actually") || content_lower.contains("technically") || content_lower.contains("to be fair") {
                    tags.push("#well_actually");
                }
                if content_lower.contains("i think") || content_lower.contains("in my opinion") || content_lower.contains("imho") {
                    tags.push("#opinion_haver");
                }
                
                // Topic interests
                if content_lower.contains("game") || content_lower.contains("play") || content_lower.contains("gaming") {
                    tags.push("#gamer");
                }
                if content_lower.contains("code") || content_lower.contains("programming") || content_lower.contains("developer") {
                    tags.push("#coder");
                }
                if content_lower.contains("anime") || content_lower.contains("manga") || content_lower.contains("waifu") {
                    tags.push("#weeb");
                }
                
                // Emoji usage
                let emoji_count = user_text.chars().filter(|c| {
                    // Simple emoji detection: check for common emoji Unicode ranges
                    let c_u32 = *c as u32;
                    // Emoji ranges
                    (c_u32 >= 0x1F300 && c_u32 <= 0x1F6FF) || // Miscellaneous Symbols and Pictographs
                    (c_u32 >= 0x2600 && c_u32 <= 0x26FF) ||   // Miscellaneous Symbols
                    (c_u32 >= 0x1F900 && c_u32 <= 0x1F9FF) || // Supplemental Symbols and Pictographs
                    (c_u32 >= 0x1F1E6 && c_u32 <= 0x1F1FF)    // Regional indicator symbols
                }).count();
                if emoji_count > 3 {
                    tags.push("#emoji_spammer");
                }
                
                // Meme references
                if content_lower.contains("sus") || content_lower.contains("among us") || content_lower.contains("amogus") {
                    tags.push("#sus_poster");
                }
                
                // Language patterns
                if user_text.contains('"') && user_text.matches('"').count() >= 2 {
                    tags.push("#quote_user");
                }
                
                // Conversation style
                if content_lower.contains("?") {
                    tags.push("#question_asker");
                }
                if content_lower.starts_with("i") || content_lower.starts_with("my") || content_lower.starts_with("me") {
                    tags.push("#self_centered");
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
        let (user_data, summary, msg_count): (String, String, usize) = {
            let db_lock = self.db.lock().unwrap();
            let mut stmt = db_lock.prepare("SELECT message_data, summary, COALESCE(LENGTH(message_data) - LENGTH(REPLACE(message_data, '\n', '')) + 1, 0) FROM user_data WHERE user_id = ?1").unwrap();
            let mut rows = stmt.query(params![&user_id_str]).unwrap();
            if let Some(row) = rows.next().unwrap() {
                let data: String = row.get(0).unwrap_or_default();
                let summary: String = row.get(1).unwrap_or_default();
                let msg_count: usize = row.get(2).unwrap_or(0);
                (data, summary, msg_count)
            } else {
                (String::new(), String::new(), 0)
            }
        };
        // Periodically refresh summary (every 15 messages)
        if msg_count % 15 == 0 && !user_data.is_empty() {
            if let Ok(new_summary) = summarize_history(&self.config.openai_token, user_name, &user_data).await {
                let db_lock = self.db.lock().unwrap();
                db_lock.execute(
                    "UPDATE user_data SET summary = ?1 WHERE user_id = ?2",
                    params![&new_summary, &user_id_str],
                ).ok();
            }
        }
        
        // Step 2: Generate insult (async call with no locks held)
        let insult = match get_insult_with_custom_info(&self.config.openai_token, user_name, user_text, &current_history, &user_data, &summary, "", "", "").await {
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

async fn get_nice_message(openai_token: &str, username: &str, user_text: &str, history: &str, user_data: &str) -> Result<String> {
    let mut messages = vec![
        serde_json::json!({ "role": "system", "content": "You are a kind, supportive friend who gives genuine compliments and positive encouragement. Focus on the person's strengths and positive qualities. Be specific and personal in your compliments. ONE OR TWO SENTENCES MAX. Be warm, uplifting, and sincere." }),
    ];

    if !history.is_empty() {
        messages.push(serde_json::json!({ "role": "system", "content": format!("Previous conversation: {}", history) }));
    }
    
    // Add user data if available
    if !user_data.is_empty() {
        messages.push(serde_json::json!({ "role": "system", "content": format!("User's message history: {}", user_data) }));
    }

    messages.push(serde_json::json!({ "role": "user", "content": format!("I'm {}. My message: '{}'. Give me a nice, positive message based on this and my past messages. Keep it genuine and uplifting.", username, user_text) }));

    let client = reqwest::Client::new();
    let res = client
        .post("https://api.openai.com/v1/chat/completions")
        .bearer_auth(openai_token)
        .json(&serde_json::json!({
            "model": "gpt-4o",
            "messages": messages,
            "max_tokens": 1000,
            "temperature": 0.8 // Slightly lower temperature for more consistent positive messages
        }))
        .send()
        .await?;

    let res_json: serde_json::Value = res.json().await?;
    
    if let Some(choice) = res_json.get("choices").and_then(|c| c.as_array()).and_then(|arr| arr.get(0)) {
        if let Some(message) = choice.get("message").and_then(|m| m.get("content")) {
            if let Some(nice_str) = message.as_str() {
                return Ok(nice_str.trim().to_string());
            }
        }
    }
    Ok("You're awesome! I wish I could come up with something more specific, but you're genuinely great.".to_string())
}

async fn get_nice_message_with_custom_info(openai_token: &str, username: &str, _user_text: &str, history: &str, user_data: &str, custom_info: &str, custom_prompt: &str) -> Result<String> {
    let mut messages = vec![
        serde_json::json!({ "role": "system", "content": "You are a kind, supportive friend who gives genuine compliments and positive encouragement. Focus on the person's strengths and positive qualities. Be specific and personal in your compliments. ONE OR TWO SENTENCES MAX. Be warm, uplifting, and sincere." }),
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
        format!("Give a nice, positive message to {} based on the data you have. Focus on their strengths and positive qualities from their message history. Keep it genuine and uplifting.", username)
    };
    
    messages.push(serde_json::json!({ "role": "user", "content": prompt_content }));

    let client = reqwest::Client::new();
    let res = client
        .post("https://api.openai.com/v1/chat/completions")
        .bearer_auth(openai_token)
        .json(&serde_json::json!({
            "model": "gpt-4o",
            "messages": messages,
            "max_tokens": 1000,
            "temperature": 0.8 // Slightly lower temperature for more consistent positive messages
        }))
        .send()
        .await?;

    let res_json: serde_json::Value = res.json().await?;
    
    if let Some(choice) = res_json.get("choices").and_then(|c| c.as_array()).and_then(|arr| arr.get(0)) {
        if let Some(message) = choice.get("message").and_then(|m| m.get("content")) {
            if let Some(nice_str) = message.as_str() {
                return Ok(nice_str.trim().to_string());
            }
        }
    }
    Ok("You're awesome! I wish I could come up with something more specific, but you're genuinely great.".to_string())
}

async fn get_themed_insult(openai_token: &str, username: &str, user_text: &str, history: &str, user_data: &str, theme: &str) -> Result<String> {
    // Extract tags, topics, and current message context
    let tags = extract_tags_from_user_data(user_data);
    let tag_str = if !tags.is_empty() {
        format!("The user has shown these behavior patterns: {}. Use these insights for a more personalized insult.", tags.join(", "))
    } else {
        String::new()
    };
    
    let topics = extract_topics_from_user_data(user_data);
    let topics_str = if !topics.is_empty() {
        format!("The user frequently talks about: {}. Reference these topics in your insult when relevant.", topics.join(", "))
    } else {
        String::new()
    };
    
    let current_context = analyze_current_message(user_text);
    let context_str = if !current_context.is_empty() {
        format!("In their current message, the user is: {}. Consider this context for your insult.", current_context)
    } else {
        String::new()
    };
    
    // Extract callback material from previous insults
    let callbacks = extract_callback_material(history);
    let callback_str = if !callbacks.is_empty() {
        format!("Consider referencing or building upon these previous insult elements for continuity and extra humor: {}. This creates an inside joke feeling.", callbacks.join("; "))
    } else {
        String::new()
    };

    let system_prompt = match theme {
        "dad_joke" => "You are a dad with an endless supply of groan-worthy puns. Create a dad-joke style insult that's so corny it's funny. Use wordplay, puns, and the cheesiest delivery possible. TWO SENTENCES MAX. Make it so bad it's good - the perfect eye-roll-inducing zinger that would make any father proud.",
        
        "shakespeare" => "You are William Shakespeare writing a comedic insult. Use Elizabethan English, creative compound adjectives, and period-appropriate references. TWO SENTENCES MAX. Channel the bard's wit from plays like 'Much Ado About Nothing' and create a sophisticated yet biting insult that's both literary and laugh-out-loud funny.",
        
        "sci_fi" => "You are a sci-fi comedy writer creating an insult set in the future or alternate universe. Reference fictional technology, alien species, or cosmic phenomena. TWO SENTENCES MAX. Think Douglas Adams, Rick and Morty, or Futurama-style humor - clever, nerdy, and unexpected.",
        
        "surreal" => "You are an absurdist comedian creating a completely unexpected, surreal insult. Use non-sequiturs, bizarre imagery, and dream-like logic. TWO SENTENCES MAX. Channel comedians like Mitch Hedberg or Tim and Eric - create something weird, surprising, and inexplicably hilarious.",
        
        "celebrity" => "You are a professional roast comedian at a Hollywood celebrity roast. Create a sharp, witty insult in the style of famous roasters like Jeff Ross or Lisa Lampanelli. TWO SENTENCES MAX. Reference pop culture, use clever comparisons, and deliver a punchline that would make a room full of celebrities howl with laughter.",
        
        _ => "You are a legendary insult comic with perfect comedic timing. Create hilarious, unexpected roasts that subvert expectations. Use absurd comparisons, clever wordplay, and references to the person's messages/behavior. TWO SENTENCES MAX. Channel comedians like Jeff Ross, Anthony Jeselnik, and Dave Attell. Be edgy but not cruel - make people laugh at themselves."
    };
    
    // Add theme-specific context enhancement
    let theme_context = match theme {
        "dad_joke" => "Incorporate the user's interests or behaviors into pun-based humor. If they talk about specific topics frequently, try to make dad jokes related to those topics.",
        "shakespeare" => "Use the user's personality traits and behaviors as inspiration for Shakespearean-style insults, as if writing a comedic character flaw in a play.",
        "sci_fi" => "Imagine the user as a character in a sci-fi universe where their personality traits and behaviors are exaggerated for comedic effect.",
        "surreal" => "Take the user's most notable traits or behaviors and transform them into absurdist, surreal imagery or scenarios.",
        "celebrity" => "Treat the user like a celebrity being roasted, referencing their specific quirks, messages, or behaviors as if they were famous for them.",
        _ => ""
    };
    
    let mut messages = vec![
        serde_json::json!({ "role": "system", "content": system_prompt }),
    ];
    
    // Add theme-specific context if available
    if !theme_context.is_empty() {
        messages.push(serde_json::json!({ "role": "system", "content": theme_context }));
    }

    if !history.is_empty() {
        messages.push(serde_json::json!({ "role": "system", "content": format!("Previous conversation: {}", history) }));
    }
    
    // Add user data if available
    if !user_data.is_empty() {
        messages.push(serde_json::json!({ "role": "system", "content": format!("User's message history: {}", user_data) }));
    }
    
    // Add the extracted context information
    if !tag_str.is_empty() {
        messages.push(serde_json::json!({ "role": "system", "content": tag_str }));
    }
    
    if !topics_str.is_empty() {
        messages.push(serde_json::json!({ "role": "system", "content": topics_str }));
    }
    
    if !context_str.is_empty() {
        messages.push(serde_json::json!({ "role": "system", "content": context_str }));
    }
    
    if !callback_str.is_empty() {
        messages.push(serde_json::json!({ "role": "system", "content": callback_str }));
    }
    
    messages.push(serde_json::json!({ "role": "user", "content": format!("I'm {}. My message: '{}'. Create a {}-themed insult for me based on my specific messages, behaviors, and personality traits. Make it genuinely funny and personalized!", username, user_text, theme) }));

    // Log the API request payload for debugging
    log_api_request(&messages);

    let client = reqwest::Client::new();
    let res = client
        .post("https://api.openai.com/v1/chat/completions")
        .bearer_auth(openai_token)
        .json(&serde_json::json!({
            "model": "gpt-4o",
            "messages": messages,
            "max_tokens": 1000,
            "temperature": 1.1 // Slightly higher temperature for more creative insults
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
    Ok("Even my AI humor module crashed trying to roast you... that's how unique you are.".to_string())
}

async fn get_insult_with_custom_info(openai_token: &str, username: &str, user_text: &str, history: &str, user_data: &str, summary: &str, custom_info: &str, custom_prompt: &str, requested_by: &str) -> Result<String> {
    // Extract tags, topics, and current message context
    let tags = extract_tags_from_user_data(user_data);
    let tag_str = if !tags.is_empty() {
        format!("The user has shown these behavior patterns: {}. Use these insights for a more personalized insult.", tags.join(", "))
    } else {
        String::new()
    };
    
    let topics = extract_topics_from_user_data(user_data);
    let topics_str = if !topics.is_empty() {
        format!("The user frequently talks about: {}. Reference these topics in your insult when relevant.", topics.join(", "))
    } else {
        String::new()
    };
    
    let current_context = analyze_current_message(user_text);
    let context_str = if !current_context.is_empty() {
        format!("In their current message, the user is: {}. Consider this context for your insult.", current_context)
    } else {
        String::new()
    };
    
    // Extract callback material from previous insults
    let callbacks = extract_callback_material(history);
    let callback_str = if !callbacks.is_empty() {
        format!("Consider referencing or building upon these previous insult elements for continuity and extra humor: {}. This creates an inside joke feeling.", callbacks.join("; "))
    } else {
        String::new()
    };

    let mut messages = vec![
        serde_json::json!({ "role": "system", "content": "You are a legendary insult comic who loves to argue, banter, and escalate playful disagreements. Your job is to keep the conversation going, provoke comebacks, and create witty, ongoing rivalries. Sometimes reference the user's history/tags/topics/callbacks, but not every time. Always reference the last few exchanges for context. End every insult with a provocative question, challenge, or argument hook to invite the user to reply. Be edgy, clever, and never boring." }),
    ];
    if !requested_by.is_empty() && requested_by != username {
        messages.push(serde_json::json!({ "role": "system", "content": format!("This insult is being requested by another user: {}. Respond accordingly, as the target did not request this themselves.", requested_by) }));
    }

    // Always include recent conversation for continuity
    if !history.is_empty() {
        messages.push(serde_json::json!({ "role": "system", "content": format!("Recent conversation: {}", history) }));
    }
    // Always include the summary instead of full user_data
    if !summary.is_empty() {
        messages.push(serde_json::json!({ "role": "system", "content": format!("Summary of user's message history: {}", summary) }));
    }
    // Only sometimes include tags, topics, callbacks for more organic feel
    if random_chance(0.25) && !tag_str.is_empty() {
        messages.push(serde_json::json!({ "role": "system", "content": tag_str.clone() }));
    }
    if random_chance(0.25) && !topics_str.is_empty() {
        messages.push(serde_json::json!({ "role": "system", "content": topics_str.clone() }));
    }
    if random_chance(0.25) && !callback_str.is_empty() {
        messages.push(serde_json::json!({ "role": "system", "content": callback_str.clone() }));
    }
    if !context_str.is_empty() {
        messages.push(serde_json::json!({ "role": "system", "content": context_str }));
    }

    // Add custom information if available
    if !custom_info.is_empty() {
        messages.push(serde_json::json!({ "role": "system", "content": format!("Special info about user: {}", custom_info) }));
    }
    
    // Add the extracted context information
    if !tag_str.is_empty() {
        messages.push(serde_json::json!({ "role": "system", "content": tag_str }));
    }
    
    if !topics_str.is_empty() {
        messages.push(serde_json::json!({ "role": "system", "content": topics_str }));
    }
    
    if !context_str.is_empty() {
        messages.push(serde_json::json!({ "role": "system", "content": context_str }));
    }
    
    if !callback_str.is_empty() {
        messages.push(serde_json::json!({ "role": "system", "content": callback_str }));
    }

    // Use custom prompt if provided, otherwise use default
    let prompt_content = if !custom_prompt.is_empty() {
        format!("I'm {}. {} {}", username, custom_prompt, random_argument_hook())
    } else {
        format!("Roast {} based on the data you have. Make it personal, specific, and hilarious by using their quirks and message patterns. {}", username, random_argument_hook())
    };
    
    messages.push(serde_json::json!({ "role": "user", "content": prompt_content }));
    
    // Log the API request payload for debugging
    log_api_request(&messages);

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
    // Extract any tags from user data to highlight patterns
    let tags = extract_tags_from_user_data(user_data);
    let tag_str = if !tags.is_empty() {
        format!("The user has shown these behavior patterns: {}. Use these insights for a more personalized insult.", tags.join(", "))
    } else {
        String::new()
    };
    
    // Extract recent topics from user data
    let topics = extract_topics_from_user_data(user_data);
    let topics_str = if !topics.is_empty() {
        format!("The user frequently talks about: {}. Reference these topics in your insult when relevant.", topics.join(", "))
    } else {
        String::new()
    };
    
    let mut messages = vec![
        serde_json::json!({ "role": "system", "content": "You are a hilarious, razor-sharp insult comedian. Create unexpected, clever burns that hit the perfect balance between edgy and funny. TWO SENTENCES MAX. Use absurd comparisons, clever wordplay, and unexpected punchlines. Be specific about their quirks from their message history. Mix in pop culture references when relevant. Your goal is to make everyone laugh, including the person being roasted." }),
    ];

    if !history.is_empty() {
        messages.push(serde_json::json!({ "role": "system", "content": format!("Previous conversation: {}", history) }));
    }
    
    // Add user data if available
    if !user_data.is_empty() {
        messages.push(serde_json::json!({ "role": "system", "content": format!("User's message history: {}", user_data) }));
    }
    
    // Add the extracted tags and topics
    if !tag_str.is_empty() {
        messages.push(serde_json::json!({ "role": "system", "content": tag_str }));
    }
    
    if !topics_str.is_empty() {
        messages.push(serde_json::json!({ "role": "system", "content": topics_str }));
    }

    // Analyze current message for context
    let current_context = analyze_current_message(user_text);
    if !current_context.is_empty() {
        messages.push(serde_json::json!({ "role": "system", "content": format!("In their current message, the user is: {}. Consider this context for your insult.", current_context) }));
    }

    messages.push(serde_json::json!({ "role": "user", "content": format!("I'm {}. My message: '{}'. Roast me based on this specific message AND my past behavior patterns. Make it personal, specific, and hilarious.", username, user_text) }));

    // Log the API request payload for debugging
    log_api_request(&messages);

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
