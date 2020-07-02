---
layout: default
---

<div class="post-header">
<h1 class="post-title">{{  page.title  }}</h1>

<span class="post-taglist">
[{% for tag in page.tags %}{% capture tag_name %}{{ tag }}{% endcapture %}<a class="tag" href="/tags/{{ tag_name }}"><code class="language-plaintext highlighter-rouge">{{ tag_name }}</code></a>{% if forloop.last == false %},&nbsp;{% endif %}{% endfor %}]
</span>
</div>
{{ content }}
