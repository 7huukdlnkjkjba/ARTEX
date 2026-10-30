package agent

import _ "embed"

// Specialist host-side agent prompts. They live as Markdown files so they stay
// readable/reviewable, and are embedded so a single binary has no runtime file
// dependency. Rendering goes through RenderPrompt (DB override → embedded
// default), exactly like the built-in agent prompts.
//
//go:embed prompts/exploit_author_prompt.md
var ExploitAuthorDefault string

//go:embed prompts/vulnhunter_prompt.md
var VulnHunterDefault string
