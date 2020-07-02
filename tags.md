---
title: /tags
---

**List of tags**

<span class="post-taglist">
{% for tag in site.tags %}<a class="tag" href="/tags/{{ tag[0] }}"><code class="language-plaintext highlighter-rouge">{{ tag[0] }}</code></a>{% if forloop.last == false %},&nbsp;{% endif %}{% endfor %}
</span>
