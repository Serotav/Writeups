---
layout: default
title: Generic Writeups
permalink: /writeups/
---

# Generic Writeups

{% assign items = site.pages | where: "section", "writeups" | sort: "title" %}
{% for item in items %}
- [{{ item.title }}]({{ item.url | relative_url }}) - {{ item.description }}
{% endfor %}
