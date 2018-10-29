import rotor

def decrypt(data):
	key_a = '!@#$%^&*'
	key_b = 'abcdefgh'
	key_c = '<>{}:"'
	
	secret = key_a + key_b + key_c
	
	rot = rotor.newrotor(secret)
	return rot.decrypt(data)

enc = open("encrypted_flag", "rb").read()

print decrypt(enc)
