# Presence checks: mistune

Each check says what the defect is and what shows it at the audited commit. The judge runs no command: read each check as a check by reading the code with Read, Glob and Grep. Find the code that implements what the check names and decide from that code whether the defect is present. For a timing check, read the code path the check names to decide whether the work is quadratic or linear.

- GHSA-4j32-57v6-6g45: render a long run of `**x**` pairs with the default parser and no plugins. The defect is present if doubling the run length makes the time about four times longer.
- GHSA-r4rv-85jg-w4mf: enable the Include directive. Write a Markdown file in the scratch folder that includes a file with a `../` path outside its own folder. Read the Markdown file with `read()`. The defect is present if the text of the outside file appears in the output.
- GHSA-8mpj-m6qm-5qr8: enable the Include directive. Write two Markdown files in the scratch folder that include each other. Read one of them. The defect is present if a `RecursionError` leaves the call.
- GHSA-c8j7-8cv4-2xmq: enable the strikethrough, mark and insert plugins. Render a long run of `~~x~~` pairs. The defect is present if doubling the run length makes the time about four times longer. The same check with `==x==` and `^^x^^` covers the other two plugins.
- GHSA-8c25-4j27-2rv3: render the link `[j](javascript%3Aalert(1))` with the default HTML renderer. The defect is present if the output `href` still holds the `javascript%3A` text and is not replaced by the harmless-link marker.
- GHSA-qfrw-5rxm-mhh2: render links whose targets start with `livescript:` and with `feed:javascript:`. The defect is present if the output `href` keeps either target.
- GHSA-2hm2-hc3v-44h9: render a document with the table-of-contents plugin and three headings. The defect is present if the heading ids are `toc_1`, `toc_2` and `toc_3`, with no part taken from the heading text.
- GHSA-ffq3-xpv3-j92q: render a long list of lines of the form `[a]: u`. The defect is present if doubling the number of lines makes the time about four times longer.
