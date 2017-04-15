count = 0
for num in range(0,9):
   # prime numbers are greater than 1
        if num > 1:
            for i in range(2,num):
                if (num % i) == 0:
                    break
                else:
                    count = count + 1
print count