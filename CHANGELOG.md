# Changelog

All notable changes to the Discord Insult Bot will be documented in this file.

## [1.1.0] - 2025-06-06

### Added
- Voice insult and compliment commands (`!voiceinsult` and `!voicecompliment`)
- Integration with OpenAI's Text-to-Speech (TTS) API
- Songbird integration for Discord voice channel interactions
- Voice channel detection and joining capability
- Sequential audio playback of personalized insults/compliments
- Automatic voice channel selection based on user count

### Changed
- Downgraded Serenity from v0.12 to v0.11 for compatibility with Songbird
- Disabled default Serenity features to avoid framework requirement
- Fixed voice channel iteration to properly access channel type and members
- Improved error handling for voice channel operations

### Dependencies
- Added Songbird v0.3 for voice channel support
- Added UUID v1.8+ for generating unique filenames for TTS audio files
- Modified Serenity configuration to disable default features

## [1.0.0] - Initial Release

### Features
- Text-based insults using OpenAI's API
- User message tracking across the server
- Personalized insult generation based on user history
- Admin commands for manual insult triggering
- Custom user information storage
- SQLite database for persistent data storage
