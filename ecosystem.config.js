module.exports = {
  apps: [{
    name: "discord-insulter",
    script: "cargo",
    args: "run --release",
    cwd: "/root/discord2025/insulter",
    interpreter: "none",
    autorestart: true,
    watch: false,
    max_memory_restart: "1G",
    env: {
      NODE_ENV: "production",
      RUST_BACKTRACE: "1"
    }
  }]
}
