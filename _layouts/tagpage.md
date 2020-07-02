---
layout: default
---

<p><strong>List of posts including the tag '{{ page.tag }}'</strong></p>

<ul>
{% for post in site.tags[page.tag] %}
  <li>
    {%- assign date_format = "%Y-%m-%d" -%}
    [ {{ post.date | date: date_format }} ] <a href="{{ post.url | relative_url }}">{{ post.title | escape }}</a>
  </li>
{% endfor %}
</ul>
</div>
