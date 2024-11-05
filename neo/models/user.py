import uuid


class User():
    def __init__(self, is_new = False, is_system_user=False, role_profile_name=None):
        self.username = ''
        self.new_password = ''
        self.enabled = 1
        self.first_name= ''
        self.last_name = ''
        self.role_profile_name = ''
        self.send_welcome_email = 0
        if is_new:
            self.reset_password_key = self.genkey()
            self.enabled = 0
        if role_profile_name:
            self.role_profile_name = role_profile_name
        if is_system_user:
            self.user_type = 'System User'
        else:
            self.user_type = 'Website User'


    def genkey(self) -> str:
        return uuid.uuid4().hex.upper()