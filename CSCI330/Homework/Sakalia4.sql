#Which customers did rent more then 4 horror movies
#category id for horror = 11
###########################CANNOT REDUCE TO 
SELECT first_name, last_name, count(*) rentals
FROM customer AS c
JOIN rental AS r USING (customer_id)
JOIN inventory AS i USING (inventory_id)
JOIN film AS f USING (film_id)
JOIN film_category AS fc USING (film_id)
WHERE fc.category_id = 11
GROUP BY first_name, last_name
HAVING COUNT(rentals) > 4;