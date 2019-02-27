#Which customers did see the movie with SCARLETT BENING?	
SELECT c.first_name, c.last_name
FROM customer AS c
JOIN rental AS r USING (customer_id)
JOIN inventory AS i USING (inventory_id)
JOIN film AS f USING (film_id)
JOIN film_actor AS fa USING(film_id)
JOIN actor AS a USING(actor_id)
WHERE a.first_name = "SCARLETT" AND a.last_name = "BENING";