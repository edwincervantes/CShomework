#Which customers at postal code 62703 saw documentaries?
#Category id of documentaries is 6
#SELECT category_id
#FROM category
#WHERE name = "documentary";
SELECT DISTINCT c.first_name, c.last_name
FROM customer AS c
JOIN rental AS r USING (customer_id)
JOIN address AS a USING (address_id)
JOIN inventory AS i USING (inventory_id)
JOIN film AS f USING (film_id)
JOIN film_category AS fc USING (film_id)
WHERE fc.category_id = 6 AND a.postal_code = 62703
