id: php
version: 2
languages: php

# PHP analysis guidelines

These analysis guidelines apply to PHP entry, SQL, command, filesystem, rendering and interpreter evidence.

## Posture

Report a confirmed injection and weak or poor practice. An agent can harden both cheaply. Unproven exploitability does not remove the finding.

## Validation

Restrict each field as far as its business requirement allows. A missing check alone does not establish a business requirement or a validation defect. Assess required presence, type, format, range and other constraints only when the supplied code or explicit scan check establishes that policy. Unknown business requirements stay uncertain. A cast, a type check or a length limit does not replace sink-specific protection. A name, a comment, or an unshown helper is not validation.

## Free text

Comments, messages, descriptions, reviews, feedback, and notes may contain any character. Do not require an allow-list. The injection control is the sink.

## Sinks

Do not build SQL text with string interpolation, concatenation, or heredoc interpolation. Pass values through prepared-statement binding (mysqli_prepare with bind_param, PDO prepare with bindParam/bindValue, SQLite3 prepare with bindValue). A bound parameter is sufficient protection for statement structure even when validation is weak. `mysqli_real_escape_string` is a value transform for SQL syntax, not binding: an escaped value interpolated into SQL text remains a construction finding. A type or length check does not make an interpolated statement safe.

## Rendering

PHP echo, print, `<?= ?>` and string interpolation emit HTML directly; nothing autoescapes. Text outside PHP tags is page markup, and the output context is the markup position where the PHP tag sits: inside a quoted attribute value (`value="<?php echo $x ?>"`) it is an HTML attribute, inside href/src/action it is a URL, inside an event-handler or style attribute it is an active attribute, inside `<script>` it is script, otherwise HTML text. A request value that reaches echo/print inside an HTML string is a reflected rendering claim. htmlspecialchars and htmlentities (with ENT_QUOTES or their actual flags recorded) escape HTML text and quoted attributes; they do not establish script, URL-scheme, CSS or unquoted-attribute safety. When an XSS path states its own `output_context`, that is where that path's value lands in the constructed string, including markup built in a helper and echoed later; judge each path in its own context. A cookie value is request input the client sends, like a query or form field: a raw cookie value rendered into markup is a supported source path. Whether an attacker can set another user's cookie is a delivery question the scanner does not establish; it alone does not make exposure unknown. Values stored through SQL INSERT and later read and echoed are stored rendering claims; the storage link must resolve the writing entry. JSON output and Content-Type changes are not HTML sinks.

## Do not claim

Do not invent a guard, a binding, a branch, or an include target that the evidence does not show. A condition in one security-level alternative never protects a sibling alternative. An unknown function or a locally defined function shadowing a builtin name carries no builtin contract.
