
Check to see if name is stored by

curl -XGET http://127.0.0.1:5000/name/YourName

Add your name, age, and occupation by 

curl -XPOST http:127.0.0.1:5000/name/YourName -H “Content-Type: application/json” --data ‘{“name”: “Yourname”. “age”: “Yourage”, “occupation”: “YourOccupation”}’


See example above

 

