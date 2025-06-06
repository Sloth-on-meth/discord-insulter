# Discord Insult Bot

A Discord bot written in Rust that delivers 4chan-style insults to users in a specific channel using OpenAI's API. The bot tracks user messages across the server to create personalized insults and can be controlled through an admin channel.

## Setup

1. **Clone the repo and install Rust**
2. **Create a Discord bot and get its token**
   - Make sure to enable the "Message Content Intent" in the Discord Developer Portal
   - Give the bot permissions to read messages, send messages, and read message history
3. **Get your OpenAI API key**
4. **Create a `config.json` file in the root directory:**

```json
{
    "discord_token": "YOUR_DISCORD_BOT_TOKEN_HERE",
    "openai_token": "YOUR_OPENAI_API_KEY_HERE",
    "insult_channel_id": "YOUR_CHANNEL_ID_HERE",
    "admin_channel_id": "YOUR_ADMIN_CHANNEL_ID_HERE"
}
```

5. **Run the bot:**

```bash
cargo run --release
```

## Features

### Core Functionality
- Delivers 4chan-style insults with greentext, memes, and typical vernacular
- Tracks user message history across the entire server for personalized insults
- Stores conversation history per user for contextual interactions
- Only insults users in the configured insult channel
- Uses OpenAI's API with 1000 token limit for detailed insults

### Admin Commands
In the admin channel, you can use the following commands:

- `!addinfo @user <custom information>` - Add custom information about a user that will be incorporated into insults
- `!insult @user` - Generate and send an insult to the mentioned user in the insult channel
- `!voiceinsult` - Join the voice channel with the most users and deliver personalized voice insults to each user
- `!voicecompliment` - Join the voice channel with the most users and deliver personalized voice compliments to each user
- `!help` - Show the list of available admin commands

### Technical Features
- Written in Rust for high performance and memory safety
- Uses SQLite database to store user message history and custom information
- Implements proper async/await patterns to avoid blocking Discord API calls
- Handles Rust's ownership system correctly to prevent Send trait issues
- Securely stores sensitive configuration in config.json (excluded from git)
- Integrates with OpenAI's Text-to-Speech API for voice insults and compliments
- Uses Songbird for Discord voice channel interactions and audio playback

## Database Structure

The bot uses three SQLite tables to store data:

1. **user_history** - Stores conversation history between the bot and users
   - `user_id`: Discord user ID (primary key)
   - `history`: Text record of conversation history

2. **user_data** - Stores message data collected from all channels
   - `user_id`: Discord user ID (primary key)
   - `message_data`: Collection of user messages
   - `last_updated`: Timestamp of last update

3. **custom_user_info** - Stores admin-provided information about users
   - `user_id`: Discord user ID (primary key)
   - `info`: Custom information for insult generation

## How It Works

1. The bot monitors all messages in the server to build a profile of each user's messaging patterns
2. When a user sends a message in the insult channel, the bot generates a personalized insult
3. The insult is based on the user's message history, past conversations, and any custom information
4. Admins can add specific information about users and trigger insults manually

## Customization

You can modify the following constants in the code:
- `MAX_HISTORY_CHARS`: Maximum characters for conversation history (default: 2000)
- `MAX_USER_DATA_CHARS`: Maximum characters for user data collection (default: 5000)

You can also adjust the OpenAI parameters in the `get_insult` and `get_insult_with_custom_info` functions:
- `max_tokens`: Maximum length of generated insults (default: 1000)
- `temperature`: Creativity level of the AI (default: 0.8)
