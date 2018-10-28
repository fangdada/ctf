class AES_tools(object):

    
    def padding_string(self,string):
        
        return string+' '*(16-len(string))




    def change_first_byte(self,string,count=1):

        if len(string)>16:
            return 'string to be changed no more than 16 bytes'

        seed=string[0]
        strings=self.padding_string(string)
        result=strings

        for i in range(1,count+1):
            result+=(chr(ord(seed)^i)+strings[1:])

        return result




