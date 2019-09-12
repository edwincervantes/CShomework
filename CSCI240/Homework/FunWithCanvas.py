# Import the Canvas class
from canvasapi import Canvas

# Canvas API URL
API_URL = "https://canvas.xavier.edu"
# Canvas API key
API_KEY = "1459~JxCV04trCvo79sIt0xW7dHUGbufhnv3c0ChcxK0vzxWOzPdOyat5ccAEDbPVZsmv"

# Initialize a new Canvas object
canvas = Canvas(API_URL, API_KEY)

user = canvas.get_user(31028)
courses = user.get_courses()

for course in courses:
	print(course)

