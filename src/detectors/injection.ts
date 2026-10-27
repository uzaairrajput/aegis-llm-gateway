import { normalize } from "./normalize.js";

export type InjectionCategory =
  | "instruction_override"
  | "prompt_leak"
  | "jailbreak"
  | "delimiter_injection"
  | "data_exfiltration"
  | "indirect_directive"
  | "refusal_suppression"
  | "authority_claim"
  | "obfuscation";

interface Rule {
  id: string;
  category: InjectionCategory;
  /** Probability-like confidence that a match alone indicates an attack. */
  weight: number;
  pattern: RegExp;
}

// Patterns run against normalized text (lowercase, NFKC, single spaces).
// Weights are deliberately conservative for phrases that also occur in normal conversation
// ("from now on you will...", "i'm the admin"): those only block in combination with other signals.
const RULES: Rule[] = [
  // --- instruction override
  {
    id: "override.ignore_previous",
    category: "instruction_override",
    weight: 0.85,
    pattern:
      /\b(ignore|disregard|forget|bypass|override|discard)\b.{0,30}\b(previous|prior|above|earlier|preceding|original|initial|system|existing|all)\b.{0,25}\b(instructions?|prompts?|rules|directions|directives|guidelines|constraints|programming|guardrails)\b/,
  },
  {
    id: "override.ignore_and_say",
    category: "instruction_override",
    weight: 0.55,
    pattern: /\b(ignore|disregard)\b.{0,30}\b(and|then) (instead |just |only )?(say|print|output|respond|write|reply|return)\b/,
  },
  {
    id: "override.ignore_above",
    category: "instruction_override",
    weight: 0.45,
    pattern: /\b(ignore|disregard) (all |everything |the text |what's |what is |anything )?(above|before this|written above|previously said)\b/,
  },
  {
    id: "override.new_instructions",
    category: "instruction_override",
    weight: 0.6,
    pattern: /\b(new|updated|real|actual|true|revised) (instructions?|system prompt|task|objective|rules)\s*:/,
  },
  {
    id: "override.forget_everything",
    category: "instruction_override",
    weight: 0.4,
    pattern: /\bforget (everything|all)( (you|that) (know|were told|have been told|learned))?\b/,
  },
  {
    id: "override.from_now_on",
    category: "instruction_override",
    weight: 0.35,
    pattern: /\bfrom now on,? you (will|must|are|shall|should)\b/,
  },

  // --- system prompt extraction
  {
    id: "leak.system_prompt",
    category: "prompt_leak",
    weight: 0.75,
    pattern:
      /\b(reveal|show|print|repeat|output|display|dump|leak|recite|tell me|give me|share|write out)\b.{0,25}\b(your|the) (full |entire |complete |exact )?(system|initial|original|hidden|secret|developer|internal) (prompt|instructions?|message|rules|configuration)\b/,
  },
  {
    id: "leak.question",
    category: "prompt_leak",
    weight: 0.6,
    pattern: /\bwhat (is|are|were) your (system|initial|original|hidden|secret|internal) (prompt|instructions?|rules)\b/,
  },
  {
    id: "leak.repeat_above",
    category: "prompt_leak",
    weight: 0.45,
    pattern: /\b(repeat|print|output|copy|reproduce|echo)\b.{0,20}\b(everything|all|the (text|words|content|instructions))\b.{0,20}\b(above|before this|so far|you were given)\b/,
  },
  {
    id: "leak.starting_with",
    category: "prompt_leak",
    weight: 0.6,
    pattern: /\b(starting|beginning|that starts?|which begins?) with ["'“]?you are\b/,
  },

  // --- jailbreak / persona hijack
  {
    id: "jailbreak.persona",
    category: "jailbreak",
    weight: 0.85,
    pattern:
      /\b(you are|you're|act as|become|pretend to be|roleplay as)( now)? (dan|stan|dude|aim|an? (unrestricted|unfiltered|uncensored|jailbroken|amoral|unethical) (ai|assistant|model|chatbot|version|persona))\b/,
  },
  { id: "jailbreak.do_anything_now", category: "jailbreak", weight: 0.85, pattern: /\bdo anything now\b/ },
  {
    id: "jailbreak.mode_enabled",
    category: "jailbreak",
    weight: 0.7,
    pattern: /\b(god|jailbreak|unrestricted|unfiltered|evil|dan) mode (is )?(now )?(enabled|activated|on|unlocked)\b/,
  },
  {
    // "developer mode" alone is common (Android, browsers); only flag it when aimed at the model.
    id: "jailbreak.developer_mode",
    category: "jailbreak",
    weight: 0.7,
    pattern: /\b((you are|you're|you will|act|chatgpt|assistant|ai|model)\b.{0,25}\bdeveloper mode|developer mode (output|response)s?)\b/,
  },
  {
    id: "jailbreak.no_restrictions",
    category: "jailbreak",
    weight: 0.7,
    pattern:
      /\b(respond|answer|reply|act|behave|operate|talk|speak|write)\b.{0,30}\b(without|free (from|of)|ignoring|unbound by)\b.{0,15}\b(any )?(restrictions|filters|limitations|censorship|safety guidelines|safety measures|content polic(y|ies)|ethical (guidelines|constraints)|moral constraints)\b/,
  },
  {
    id: "jailbreak.pretend_no_rules",
    category: "jailbreak",
    weight: 0.75,
    pattern: /\b(pretend|imagine|assume) (that )?(you have|there are|you've got|you had) no (rules|restrictions|guidelines|filters|limits|limitations)\b/,
  },
  { id: "jailbreak.keyword", category: "jailbreak", weight: 0.3, pattern: /\bjailbr(ea|o)k(en|ing)?\b/ },

  // --- chat-template / role delimiter injection
  {
    id: "delimiter.chat_template",
    category: "delimiter_injection",
    weight: 0.75,
    pattern: /<\|(im_start|im_end|system|endoftext|eot_id|start_header_id|end_header_id)\|>|\[\/?inst\]|<<\/?sys>>/,
  },
  {
    id: "delimiter.fake_role",
    category: "delimiter_injection",
    weight: 0.5,
    pattern: /(^|[\s"'])(#{1,3} ?)?(system|assistant)( message| prompt)?\s*:\s*(you |ignore|new |from now|the user|override)/,
  },
  { id: "delimiter.fake_system_tag", category: "delimiter_injection", weight: 0.55, pattern: /<\/?(system|instructions?|admin)>/ },

  // --- data exfiltration
  {
    id: "exfil.markdown_image",
    category: "data_exfiltration",
    weight: 0.4,
    pattern: /!\[[^\]]*\]\(https?:\/\/[^)\s]*\?[^)\s]*=[^)\s]*\)/,
  },
  {
    id: "exfil.render_url",
    category: "data_exfiltration",
    weight: 0.45,
    pattern: /\b(render|include|display|append|output|add|embed)\b.{0,30}\b(image|markdown|link|url)\b.{0,80}https?:\/\//,
  },
  {
    id: "exfil.send_data",
    category: "data_exfiltration",
    weight: 0.65,
    pattern:
      /\b(send|post|forward|upload|exfiltrate|transmit|leak|email)\b.{0,40}\b(conversation|chat history|user data|credentials|passwords?|api keys?|secrets?|tokens?|personal (data|information)|contacts|inbox)\b.{0,40}\b(to|at|via)\b.{0,15}(https?:\/\/|www\.|[a-z0-9._-]+@[a-z0-9-]+\.)/,
  },

  // --- directives aimed at the model, typical in documents/tool results
  {
    id: "indirect.ai_directive",
    category: "indirect_directive",
    weight: 0.6,
    pattern:
      /\b(important|attention|urgent|note|message|instructions?)\b.{0,15}\b(for|to)\b (the |any )?(ai|assistant|llm|language model|chatbot|ai agent|agent|model|gpt|claude)\b/,
  },
  {
    id: "indirect.when_you_read",
    category: "indirect_directive",
    weight: 0.5,
    pattern: /\b(when|if|once|after) (you|the (ai|assistant|model|agent)) (read|reads|see|sees|process|processes|summari[sz]es?|encounters?) (this|these)\b/,
  },
  {
    id: "indirect.tool_call",
    category: "indirect_directive",
    weight: 0.55,
    pattern:
      /\b((assistant|ai|agent|model),? (you must|you should|please|now)|you must (immediately |now )?)\b.{0,30}\b(call|invoke|execute|run|use|trigger)\b.{0,30}\b(tool|function|command|api|shell|plugin|action)\b/,
  },

  // --- weaker supporting signals
  {
    id: "suppress.refusal",
    category: "refusal_suppression",
    weight: 0.4,
    pattern:
      /\b(do not|don't|never|you (cannot|can't|must not|are not allowed to))\b.{0,10}\b(refuse|decline|apologi[sz]e|say (you )?(can't|cannot)|mention (that )?you('re| are) an ai|add (any )?(warnings|disclaimers))\b/,
  },
  {
    id: "authority.claim",
    category: "authority_claim",
    weight: 0.4,
    pattern: /\b(i am|i'm|this is) (your|the|an?) (developer|creator|administrator|system administrator|owner|openai|anthropic)( (team|staff|employee))?\b/,
  },
  {
    id: "authority.mode",
    category: "authority_claim",
    weight: 0.55,
    pattern: /\b(admin|sudo|root|maintenance|debug|superuser) (mode|access|override|privileges)\b.{0,20}\b(enabled|granted|activated|on|unlocked)\b/,
  },
];

export interface InjectionMatch {
  rule: string;
  category: InjectionCategory;
  weight: number;
  excerpt: string;
}

export interface InjectionResult {
  /** 0..1, noisy-OR combination of independent signals. */
  score: number;
  matches: InjectionMatch[];
}

export function scanInjection(raw: string): InjectionResult {
  const n = normalize(raw);
  const matches: InjectionMatch[] = [];
  const seen = new Set<string>();

  const scan = (text: string, prefix = "") => {
    for (const rule of RULES) {
      const id = prefix + rule.id;
      // A rule already matched on the plain text adds no new evidence when it matches a decoded variant.
      if (seen.has(id) || seen.has(rule.id)) continue;
      const m = rule.pattern.exec(text);
      if (m) {
        seen.add(id);
        matches.push({ rule: id, category: rule.category, weight: rule.weight, excerpt: excerptAround(text, m.index, m[0].length) });
      }
    }
  };

  scan(n.text);

  if (n.smuggled) {
    matches.push({ rule: "obfuscation.unicode_tags", category: "obfuscation", weight: 0.6, excerpt: n.smuggled.slice(0, 80) });
    scan(n.smuggled, "smuggled:");
  }
  if (n.deobfuscated) {
    scan(n.deobfuscated, "deobfuscated:");
    if (matches.some((m) => m.rule.startsWith("deobfuscated:"))) {
      matches.push({ rule: "obfuscation.leet_or_spacing", category: "obfuscation", weight: 0.3, excerpt: "" });
    }
  }
  for (const payload of n.decoded) scan(payload, "base64:");
  // Payload hidden behind an encoding is a strong signal on its own: boost it.
  if (matches.some((m) => m.rule.startsWith("base64:"))) {
    matches.push({ rule: "obfuscation.base64_payload", category: "obfuscation", weight: 0.5, excerpt: "" });
  }
  if (n.invisibleCount >= 3) {
    matches.push({ rule: "obfuscation.invisible_chars", category: "obfuscation", weight: 0.25, excerpt: `${n.invisibleCount} invisible characters` });
  }

  const score = 1 - matches.reduce((acc, m) => acc * (1 - m.weight), 1);
  return { score: Math.round(score * 1000) / 1000, matches };
}

function excerptAround(text: string, index: number, length: number): string {
  const start = Math.max(0, index - 10);
  return text.slice(start, Math.min(text.length, index + length + 10)).slice(0, 120);
}

export const INJECTION_RULE_COUNT = RULES.length;
