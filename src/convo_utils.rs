use rand::Rng;

/// Returns true with the given probability (0.0 to 1.0).
pub fn random_chance(prob: f32) -> bool {
    let mut rng = rand::thread_rng();
    rng.gen::<f32>() < prob
}

/// Returns a random argument hook to provoke the user into replying.
pub fn random_argument_hook() -> &'static str {
    const HOOKS: &[&str] = &[
        "Come on, you can do better than that, can't you?",
        "Is that really your best comeback?",
        "Bet you can't roast me back!",
        "Prove me wrong, if you dare.",
        "You gonna let me get away with that?",
        "Don't tell me you're out of comebacks already.",
        "Care to argue, or just gonna take it?",
        "I expected more resistance from you.",
        "Try to change my mind, if you can.",
        "Go on, I dare you to clap back."
    ];
    let mut rng = rand::thread_rng();
    let idx = rng.gen_range(0..HOOKS.len());
    HOOKS[idx]
}
