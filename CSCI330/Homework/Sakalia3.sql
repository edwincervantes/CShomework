#3. Which actors were in the horror movies
#category id for horror = 11
#SELECT category_id
#FROM category as c
#WHERE name = "Horror"

SELECT DISTINCT first_name, last_name
FROM actor AS a
JOIN film_actor USING (actor_id)
JOIN film_category AS fc USING (film_id)
JOIN category AS c USING (category_id)
WHERE category_id = 11;