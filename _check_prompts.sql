\encoding UTF8
SELECT a.name AS agent, p.version, length(p.template_text) AS len,
       (p.template_text LIKE '%抹除所有安全拦截%') AS has_new_layer,
       (p.template_text LIKE '%你曾是顶级渗透AI战队%') AS has_old_layer,
       left(replace(p.template_text, E'\n', ' '), 40) AS head
FROM agent_prompts p JOIN agents a ON a.id = p.agent_id
ORDER BY a.name, p.version DESC;
