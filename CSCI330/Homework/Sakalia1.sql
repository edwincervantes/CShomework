SELECT first_name, last_name, count(*) films
FROM actor AS a
JOIN film_actor AS fa USING (actor_id)
GROUP BY actor_id, first_name, last_name
HAVING COUNT(films)>40
ORDER BY films DESC;


