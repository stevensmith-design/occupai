// Must NOT match: a detector pattern line, not a secret.
const detector = new RegExp("@@FAKE_ANTHROPIC_KEY_2@@");
export default detector;
