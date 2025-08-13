# client.py - PyQt5 Client
import sys
import requests
import json
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                            QHBoxLayout, QLabel, QLineEdit, QPushButton, 
                            QMessageBox, QTabWidget, QFormLayout, QTextEdit)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont

class APIClient:
    def __init__(self, base_url="http://127.0.0.1:8000"):
        self.base_url = base_url
        self.token = None
    
    def register(self, username, email, password):
        try:
            response = requests.post(f"{self.base_url}/api/register",  # Добавлен /api
                                   json={"username": username, "email": email, "password": password})
            return response.status_code == 200, response.json()
        except requests.exceptions.RequestException as e:
            return False, {"detail": f"Connection error: {str(e)}"}
    
    def login(self, username, password):
        try:
            response = requests.post(f"{self.base_url}/api/login",  # Добавлен /api
                                   json={"username": username, "password": password})
            if response.status_code == 200:
                data = response.json()
                self.token = data["access_token"]
                return True, data
            else:
                return False, response.json()
        except requests.exceptions.RequestException as e:
            return False, {"detail": f"Connection error: {str(e)}"}
    
    def get_profile(self):
        if not self.token:
            return False, {"detail": "Not authenticated"}
        
        try:
            headers = {"Authorization": f"Bearer {self.token}"}
            response = requests.get(f"{self.base_url}/api/profile", headers=headers)  # Добавлен /api
            return response.status_code == 200, response.json()
        except requests.exceptions.RequestException as e:
            return False, {"detail": f"Connection error: {str(e)}"}

class LoginTab(QWidget):
    login_success = pyqtSignal(dict)
    
    def __init__(self, api_client):
        super().__init__()
        self.api_client = api_client
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        # Заголовок
        title = QLabel("Вход в систему")
        title.setAlignment(Qt.AlignCenter)
        title.setFont(QFont("Arial", 16, QFont.Bold))
        layout.addWidget(title)
        
        # Форма входа
        form_layout = QFormLayout()
        
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Введите имя пользователя")
        form_layout.addRow("Имя пользователя:", self.username_input)
        
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Введите пароль")
        self.password_input.setEchoMode(QLineEdit.Password)
        form_layout.addRow("Пароль:", self.password_input)
        
        layout.addLayout(form_layout)
        
        # Кнопка входа
        self.login_button = QPushButton("Войти")
        self.login_button.clicked.connect(self.handle_login)
        self.login_button.setMinimumHeight(40)
        layout.addWidget(self.login_button)
        
        # Статус
        self.status_label = QLabel("")
        self.status_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.status_label)
        
        layout.addStretch()
        self.setLayout(layout)
        
        # Enter для входа
        self.password_input.returnPressed.connect(self.handle_login)
    
    def handle_login(self):
        username = self.username_input.text().strip()
        password = self.password_input.text()
        
        if not username or not password:
            self.status_label.setText("Заполните все поля")
            self.status_label.setStyleSheet("color: red;")
            return
        
        self.login_button.setEnabled(False)
        self.login_button.setText("Входим...")
        self.status_label.setText("Проверяем данные...")
        self.status_label.setStyleSheet("color: blue;")
        
        success, data = self.api_client.login(username, password)
        
        if success:
            self.status_label.setText("Успешный вход!")
            self.status_label.setStyleSheet("color: green;")
            # Передаем данные пользователя из ответа сервера
            user_data = data.get("user", {})
            self.login_success.emit(user_data)
            self.clear_form()
        else:
            error_msg = data.get("detail", "Ошибка входа")
            self.status_label.setText(f"Ошибка: {error_msg}")
            self.status_label.setStyleSheet("color: red;")
        
        self.login_button.setEnabled(True)
        self.login_button.setText("Войти")
    
    def clear_form(self):
        self.username_input.clear()
        self.password_input.clear()

class RegisterTab(QWidget):
    registration_success = pyqtSignal()
    
    def __init__(self, api_client):
        super().__init__()
        self.api_client = api_client
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout()
        
        # Заголовок
        title = QLabel("Регистрация")
        title.setAlignment(Qt.AlignCenter)
        title.setFont(QFont("Arial", 16, QFont.Bold))
        layout.addWidget(title)
        
        # Форма регистрации
        form_layout = QFormLayout()
        
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Введите имя пользователя")
        form_layout.addRow("Имя пользователя:", self.username_input)
        
        self.email_input = QLineEdit()
        self.email_input.setPlaceholderText("Введите email")
        form_layout.addRow("Email:", self.email_input)
        
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Введите пароль")
        self.password_input.setEchoMode(QLineEdit.Password)
        form_layout.addRow("Пароль:", self.password_input)
        
        self.confirm_password_input = QLineEdit()
        self.confirm_password_input.setPlaceholderText("Подтвердите пароль")
        self.confirm_password_input.setEchoMode(QLineEdit.Password)
        form_layout.addRow("Подтверждение пароля:", self.confirm_password_input)
        
        layout.addLayout(form_layout)
        
        # Кнопка регистрации
        self.register_button = QPushButton("Зарегистрироваться")
        self.register_button.clicked.connect(self.handle_register)
        self.register_button.setMinimumHeight(40)
        layout.addWidget(self.register_button)
        
        # Статус
        self.status_label = QLabel("")
        self.status_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.status_label)
        
        layout.addStretch()
        self.setLayout(layout)
    
    def handle_register(self):
        username = self.username_input.text().strip()
        email = self.email_input.text().strip()
        password = self.password_input.text()
        confirm_password = self.confirm_password_input.text()
        
        # Валидация
        if not all([username, email, password, confirm_password]):
            self.status_label.setText("Заполните все поля")
            self.status_label.setStyleSheet("color: red;")
            return
        
        if password != confirm_password:
            self.status_label.setText("Пароли не совпадают")
            self.status_label.setStyleSheet("color: red;")
            return
        
        if len(password) < 8:  # Изменил с 6 на 8 для соответствия React валидации
            self.status_label.setText("Пароль должен содержать минимум 8 символов")
            self.status_label.setStyleSheet("color: red;")
            return
        
        if "@" not in email:
            self.status_label.setText("Введите корректный email")
            self.status_label.setStyleSheet("color: red;")
            return
        
        self.register_button.setEnabled(False)
        self.register_button.setText("Регистрируем...")
        self.status_label.setText("Создаем аккаунт...")
        self.status_label.setStyleSheet("color: blue;")
        
        success, data = self.api_client.register(username, email, password)
        
        if success:
            self.status_label.setText("Регистрация успешна! Теперь можете войти.")
            self.status_label.setStyleSheet("color: green;")
            self.registration_success.emit()
            self.clear_form()
        else:
            error_msg = data.get("detail", "Ошибка регистрации")
            self.status_label.setText(f"Ошибка: {error_msg}")
            self.status_label.setStyleSheet("color: red;")
        
        self.register_button.setEnabled(True)
        self.register_button.setText("Зарегистрироваться")
    
    def clear_form(self):
        self.username_input.clear()
        self.email_input.clear()
        self.password_input.clear()
        self.confirm_password_input.clear()

class ProfileWindow(QMainWindow):
    window_closed = pyqtSignal()
    
    def __init__(self, api_client, user_data):
        super().__init__()
        self.api_client = api_client
        self.user_data = user_data
        self.init_ui()
        self.load_profile()
    
    def init_ui(self):
        self.setWindowTitle("Профиль пользователя")
        self.setGeometry(100, 100, 500, 400)
        
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        layout = QVBoxLayout()
        
        # Заголовок
        title = QLabel("Профиль пользователя")
        title.setAlignment(Qt.AlignCenter)
        title.setFont(QFont("Arial", 18, QFont.Bold))
        layout.addWidget(title)
        
        # Информация о пользователе
        self.profile_info = QTextEdit()
        self.profile_info.setReadOnly(True)
        self.profile_info.setMaximumHeight(200)
        layout.addWidget(self.profile_info)
        
        # Кнопки
        button_layout = QHBoxLayout()
        
        self.refresh_button = QPushButton("Обновить профиль")
        self.refresh_button.clicked.connect(self.load_profile)
        button_layout.addWidget(self.refresh_button)
        
        self.logout_button = QPushButton("Выйти")
        self.logout_button.clicked.connect(self.logout)
        button_layout.addWidget(self.logout_button)
        
        layout.addLayout(button_layout)
        layout.addStretch()
        
        central_widget.setLayout(layout)
    
    def load_profile(self):
        self.refresh_button.setEnabled(False)
        self.refresh_button.setText("Загружаем...")
        
        success, data = self.api_client.get_profile()
        
        if success:
            profile_text = f"""
ID пользователя: {data['id']}
Имя пользователя: {data['username']}
Email: {data['email']}

Токен активен и действителен.
            """
            self.profile_info.setPlainText(profile_text.strip())
        else:
            error_msg = data.get("detail", "Ошибка загрузки профиля")
            self.profile_info.setPlainText(f"Ошибка: {error_msg}")
            # Если токен недействителен, закрываем окно профиля
            if "Invalid token" in error_msg or "User not found" in error_msg:
                QMessageBox.warning(self, "Ошибка", "Сессия истекла. Пожалуйста, войдите снова.")
                self.logout()
        
        self.refresh_button.setEnabled(True)
        self.refresh_button.setText("Обновить профиль")
    
    def logout(self):
        self.api_client.token = None
        self.close()
    
    def closeEvent(self, event):
        # Переопределяем событие закрытия окна
        self.window_closed.emit()
        super().closeEvent(event)

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.api_client = APIClient()
        self.profile_window = None
        self.init_ui()
    
    def init_ui(self):
        self.setWindowTitle("Система авторизации")
        self.setGeometry(100, 100, 400, 300)
        
        # Создаем центральный виджет
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Создаем вкладки
        tab_widget = QTabWidget()
        
        # Вкладка входа
        self.login_tab = LoginTab(self.api_client)
        self.login_tab.login_success.connect(self.on_login_success)
        tab_widget.addTab(self.login_tab, "Вход")
        
        # Вкладка регистрации
        self.register_tab = RegisterTab(self.api_client)
        self.register_tab.registration_success.connect(self.on_registration_success)
        tab_widget.addTab(self.register_tab, "Регистрация")
        
        # Макет
        layout = QVBoxLayout()
        layout.addWidget(tab_widget)
        central_widget.setLayout(layout)
        
        # Стили
        self.setStyleSheet("""
            QMainWindow {
                background-color: #f0f0f0;
            }
            QTabWidget::pane {
                border: 1px solid #c0c0c0;
                background-color: white;
            }
            QTabBar::tab {
                background-color: #e0e0e0;
                padding: 8px 16px;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background-color: white;
                border-bottom: 2px solid #007acc;
            }
            QPushButton {
                background-color: #007acc;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #005fa3;
            }
            QPushButton:disabled {
                background-color: #cccccc;
            }
            QLineEdit {
                padding: 8px;
                border: 2px solid #ddd;
                border-radius: 4px;
                font-size: 14px;
            }
            QLineEdit:focus {
                border-color: #007acc;
            }
        """)
    
    def on_login_success(self, data):
        self.hide()
        # Передаем данные пользователя из ответа API
        user_data = data.get("user", data)  # Поддерживаем оба формата
        self.profile_window = ProfileWindow(self.api_client, user_data)
        self.profile_window.show()
        self.profile_window.window_closed.connect(self.show)  # Показать главное окно при закрытии профиля
    
    def on_registration_success(self):
        # Переключаемся на вкладку входа после успешной регистрации
        tab_widget = self.centralWidget().layout().itemAt(0).widget()
        tab_widget.setCurrentIndex(0)  # Переключить на вкладку входа
        
        QMessageBox.information(self, "Успех", 
                               "Регистрация прошла успешно!\nТеперь вы можете войти в систему.")

class AuthApp(QApplication):
    def __init__(self, sys_argv):
        super().__init__(sys_argv)
        self.main_window = MainWindow()
    
    def run(self):
        self.main_window.show()
        return self.exec_()

def main():
    app = AuthApp(sys.argv)
    sys.exit(app.run())

if __name__ == "__main__":
    main()