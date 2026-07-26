---
layout: default
title: Serotav Writeups
---

# Serotav Writeups

CTF/pwn writeups and browser exploitation notes.

{% assign posts = site.pages | where_exp: "post", "post.date" | sort: "date" | reverse %}
{% for post in posts %}
<article>
  <h2><a href="{{ post.url | relative_url }}">{{ post.title }}</a></h2>
  <time datetime="{{ post.date | date_to_xmlschema }}">{{ post.date | date: "%B %-d, %Y" }}</time>
  <p><a href="{{ post.url | relative_url }}">{{ post.content | markdownify | strip_html | normalize_whitespace | truncatewords: 45 }}</a></p>
</article>
{% endfor %}
