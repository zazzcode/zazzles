# Twig coverage

[Detection capabilities](../detection-capabilities.md) · [Symfony coverage](symfony.md) · [Cross-site scripting](cross-site-scripting.md) · [Template injection](template-injection.md)

Code Scan reads the Twig templates a Symfony action renders and records each `{{ ... }}` output
that carries a request or stored value. The claim is [cross-site scripting](cross-site-scripting.md):
one value in one browser output context. Twig escapes the final value of an output unless the
outermost operation is marked safe, so the scanner decides protection from that outermost
operation and from the markup around the output.

## Templates and variables

| Form | Example | What the scanner establishes |
| --- | --- | --- |
| Rendered template | `$this->render('blog/post.html.twig', ['post' => $post])`, `renderView`, `renderBlock` | The template file and its context variables |
| Composition | `{% extends 'base.html.twig' %}`, `{% include 'part.html.twig' %}`, `{{ include('part.html.twig', {v: q}) }}`, `{% block %}` | The included or parent template with the caller's variables |
| Local variables | `{% set v = q %}`, `{% for item in items %}` | The same value under the new name |
| Request access | `app.request.query.get('q')`, `app.request.get('q')`, headers and cookies | The same request field as in PHP |
| Session user and flashes | `app.user`, `app.flashes('error')` | The stored user entity, or the flash store for that type |
| Twig globals | A `twig.globals` entry whose value is `'@App\Services\UserPref'` | That service, constructed for every rendered template |
| Entity properties | `comment.author.username` | The getter or property of the entity, including associations |

## Output protection

The table applies to a template whose name ends in `.html.twig` under the default autoescape
strategy.

| Output | Example | Result |
| --- | --- | --- |
| Plain output in HTML text | `<p>{{ q }}</p>` | Encoded |
| Plain output in a quoted attribute | `<input value="{{ q }}">` | Encoded |
| `raw` | `{{ q\|raw }}`, `{{ q\|upper\|raw }}` | Raw |
| A raw branch of a conditional | `{{ flag ? q\|raw : 'none' }}` | Raw. Twig escapes each branch on its own |
| Explicit escape | `{{ q\|e }}`, `{{ q\|escape('html') }}` | Encoded in HTML text and quoted attributes |
| Explicit strategy | `{{ q\|e('js') }}` inside `<script>`, `e('css')`, `e('url')`, `e('html_attr')` | Encoded only in the matching context |
| `nl2br` | `{{ q\|nl2br }}` | Encoded. The filter escapes its input first |
| `spaceless` | `{{ q\|spaceless }}` | Raw. The filter is marked safe |
| Ordinary filters | `upper`, `trim`, `striptags`, `json_encode`, `replace`, `trans` | Encoded. The final value is still escaped |
| Project function or filter marked safe | `new TwigFunction('card', [...], ['is_safe' => ['html']])` | Raw. The PHP callable is followed with the template arguments |
| Project function or filter not marked safe | `new TwigFunction('plain', [...])` | Encoded |
| Autoescape block off | `{% autoescape false %}{{ q }}{% endautoescape %}` | Raw |
| Project autoescape off | `twig: { autoescape: false }` in `config/packages/twig.yaml` | Raw for every plain output |

## URL attributes

HTML escaping keeps a value inside its quoted attribute. It does not choose the URL scheme, so the
result depends on the literal text in front of the value.

| Output | Example | Result |
| --- | --- | --- |
| Literal local prefix | `<img src="{{ asset('uploads/' ~ name) }}">`, `<a href="/go/{{ q }}">` | Encoded. The prefix fixes the scheme |
| Literal `http` or `https` host | `<a href="https://example.com/u/{{ q }}">` | Encoded |
| Whole URL of a link, form or frame | `<a href="{{ q }}">`, `<form action="{{ q }}">`, `<iframe src="{{ q }}">`, `<script src="{{ q }}">` | Raw. A script URL runs |
| Whole URL of an image or media element | `<img src="{{ q }}">` | Review |
| Prefix with no path delimiter | `<a href="java{{ q }}">` | Review |
| Script, embed or stylesheet source with a prefix | `<script src="/js/{{ q }}">` | Review |
| Generated route URL | `{{ path('post', {id: q}) }}` | Not recorded. The parameters are percent-encoded |

## Recorded in Review

| ID | Form | Example | Why it is in Review |
| --- | --- | --- | --- |
| `TWIG-R01` | Script, style, event-handler or unquoted-attribute context | `<script>var a = "{{ q }}";</script>` | HTML escaping is not the encoding that context needs |
| `TWIG-R02` | Unknown filter or function | `{{ q\|mystery }}` | Whether it is marked safe is not established. Gap `twig_expression_unresolved` |
| `TWIG-R03` | Macro call | `{{ _self.badge(q) }}`, `{{ forms.input(q) }}` | A macro returns safe markup and its body is not expanded |
| `TWIG-R04` | Other autoescape strategy | `{% autoescape 'js' %}`, a custom `autoescape_service` | The escaping applied is not HTML. Gap `render_protection_unresolved` |
| `TWIG-R05` | Template that is not `.html.twig` | `mail.txt.twig` | The file name does not establish HTML autoescaping |
| `TWIG-R06` | Stored value with no linked writer | `{{ post.title }}` when the only writer is not a request | The origin of the content is unknown |

## Not recorded

| ID | Form | Example | Boundary |
| --- | --- | --- | --- |
| `TWIG-N01` | Dynamic template name | `$this->render($name)` | Entry gap `twig_template_unresolved` |
| `TWIG-N02` | Macro body | `{% macro badge(v) %}{{ v\|raw }}{% endmacro %}` | The definition is recorded as a gap. Its outputs are judged only at the call |
| `TWIG-N03` | `embed` overrides and sandbox policy | `{% embed 'card.html.twig' %}` | Outside the modeled render subset |
| `TWIG-N04` | Templates no action renders | A template included only by name computed at run time | Never reached |

## Template injection

Compiling request or stored text as a template is a separate
[template injection](template-injection.md) claim. The scanner records `createTemplate` and
`template_from_string` when a template calls a project function that compiles its argument, and
reports the stored or request value that reaches the compiler.

## Judged scans

A judged scan sends each output with the markup around it, so the decision model sees the element
and attribute the value lands in. The scanner's context and protection facts must agree with the
model's answers before a record is Confirmed or Protected.
