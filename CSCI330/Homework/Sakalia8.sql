 #Find the customer names who have rented ALL the horror films available
SELECT DISTINCT c.first_name, c.last_name
FROM customer AS c
JOIN rental AS r USING (customer_id)
JOIN inventory AS i USING (inventory_id)
JOIN film AS f USING (film_id)

SELECT title
FROM film AS f
JOIN film_category AS fc USING(film_id)
