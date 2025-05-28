# ByteSource

ByteSource is a Django-based project for managing quizzes and user progress.A dynamic Web Based application for Computer Science E-Learning.This Project was made as a part of Intercollege Hackaton Colloquium (Theme : IT for Smart Campus) 2024.Our team was Selected and was Awarded for the project.

## Installation

1. Clone the repository:

   ```sh
   git clone https://github.com/yourusername/ByteSource.git
   cd ByteSource

   ```

2. Create and activate a virtual environment:
   python3 -m venv venv
   source venv/bin/activate

3. Install the dependencies:
   pip install -r requirements.txt

4. Set up environment variables:
   cp .env.example .env

5. Apply migrations and create a superuser:
   python manage.py migrate
   python manage.py createsuperuser

6. Run the development server:
   python manage.py runserver

Usage
Access the admin panel at http://127.0.0.1:8000/admin/
Access the main page at http://127.0.0.1:8000/main/

Contributing
Contributions are welcome! Please open an issue or submit a pull request.

License
This project is licensed under the MIT License.
