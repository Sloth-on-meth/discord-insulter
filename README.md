# Discord Insult Bot

A Discord bot written in Rust that insults users in a specific channel using OpenAI's API.

## Setup

1. **Clone the repo and install Rust**
2. **Create a Discord bot and get its token**
3. **Get your OpenAI API key**
4. **Create a `config.json` file in the root directory:**

```
{
    "discord_token": "YOUR_DISCORD_BOT_TOKEN_HERE",
    "openai_token": "YOUR_OPENAI_API_KEY_HERE",
    "insult_channel_id": "YOUR_CHANNEL_ID_HERE"
}
```

5. **Run the bot:**

```
cargo run --release
```

## Features
- Only insults users in the configured channel
- Uses OpenAI's API to generate creative insults
