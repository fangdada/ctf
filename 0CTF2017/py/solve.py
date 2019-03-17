import rotor

def decrypt(data):
	key_a = '!@#$%^&*'
	key_b = 'abcdefgh'
	key_c = '<>{}:"'
	
	secret = key_a*4 + '|' + (key_b+key_a+key_c)*2 + '|' + key_b*2 + 'EOF'
	
	rot = rotor.newrotor(secret)
	return rot.decrypt(data)

i = open("encrypted_flag", "rb").read()

print decrypt(i)
