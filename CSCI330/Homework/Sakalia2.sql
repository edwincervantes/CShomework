#Which actors were in the movies in German language

SELECT first_name, last_name
FROM actor AS a
JOIN film AS f
WHERE language_id = 6

#Note language ID for German is 6
	#SELECT language_id
	#FROM language AS l
	#WHERE name = "German"
