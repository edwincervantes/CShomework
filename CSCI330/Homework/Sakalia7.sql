#Find the customer and rental title for all overdue dvd rentals
SELECT DISTINCT c.first_name, c.last_name, f.title
FROM customer AS c
JOIN rental AS r USING (customer_id)
JOIN inventory AS i USING (inventory_id)
JOIN film AS f USING (film_id)
WHERE r.return_date is NULL AND (r.rental_date + INTERVAL f.rental_duration DAY) < current_date();