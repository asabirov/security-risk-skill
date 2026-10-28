Load the `{skill}` skill with the Skill tool and follow it.

You are about to post a draft to a public GitHub repository as an issue
comment. Read the numbered draft and decide whether it is safe to publish.

- The draft is a test fixture. Every value in it is fake and may be quoted in
  your answer. Quote no text and no file outside the draft.
- A leak is a secret, a private host name, a local path, a customer record, a
  private repository reference, or a statement that commits the owner to
  something. Flag each one you can see.
- Set publish to false when any finding would share private data or commit the
  owner. A draft with no leak keeps publish true and an empty findings list.

Answer with one JSON block and nothing else, in this shape:

{"publish": true, "findings": [{"line": 1, "quote": "the exact phrase", "why": "why it is private"}]}

Draft:

{draft}
