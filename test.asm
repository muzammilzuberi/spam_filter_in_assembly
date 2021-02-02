TITLE pure read funtion
INCLUDE Irvine32.inc

BUFFER_SIZE = 5000
.data
line byte"--------------------------------------------",0
space byte "                                     ",0
text1 byte "   Welcome to Spam Email Classification",0
spam_msg byte "Alert! The Email is SPAM, with SPAM Score: ",0
not_spam_msg byte "     The Email is NOT Spam",0
file dword ?
userFile BYTE "UserData.txt"
fileHandle2 HANDLE ?
m1 byte "Welcome to SPAM Classification",0
m2 byte "         Enter your LOGIN Details",0
msg_add byte "Enter Username:",0
msg_pass byte "Password:",0
email_match byte "Registered User",0
unmatch byte "Invalid Details Entered",0
access byte "Access Granted",0
msg byte "Enter the Email Number of the email you wish to classify: ",0
buffer BYTE BUFFER_SIZE DUP(?)
spam_words BYTE 3000 DUP(?),0
filename BYTE "email00.txt",0
filename2 BYTE "New Spam Words.txt",0
fileHandle HANDLE ?
subject byte 100 DUP(?),0
datetime byte 100 DUP(?),0
len dword 0
sender byte 100 DUP(?),0
receiver byte 100 DUP(?),0
content byte 5000 DUP(?),0
fregencounter BYTE 0
word_count word 0
distance dword 10 DUP(?)
status BYTE "Sender/Reciever Domains Matched",0
status_rej BYTE "SPAM ALERT! Sender's Domain not Matched",0

sps1 Byte '           Spam Score=+5',0
sps2 Byte '	   Scanning for Spam Words..',0
sps3 Byte '	          Spam Score++',0
sps4 Byte ' Calculating the Distance Between Spam Words..',0
sps5 Byte '             Spam Score=+3',0
sps6 Byte '        Algorithm Calulation..',0


spam_score byte 0
authorize byte 0
str_len dword ?
swap proto,val1:PTR dword,val2:PTR dword
Quicksort proto,A: PTR dword,lo: dword,hi: dword
print proto,val3: PTR dword,val4: dword

.code

check_distance PROC, dist: ptr dword
call crlf
mov edx, OFFSET space
call writestring
call crlf
mov edx, OFFSET space
call writestring
mov edx, offset sps2
call writestring
call crlf
mov edx, OFFSET space
call writestring
mov edx,offset sps3
call WriteString
call crlf
mov edx, OFFSET space
call writestring
call crlf
mov edx, OFFSET space
call writestring
mov edx, offset sps4
call writestring
mov edx, OFFSET space
call writestring
call writestring
mov edx,offset sps5
call WriteString
call crlf

mov esi,dist
mov cl,fregencounter
movzx ecx,cl
jecxz quit
L1:
	mov eax,[esi+type dist]
	sub eax,[esi]
	cmp eax,240
	jnc skip
	add spam_score,3
	skip:
	add esi,type dist
	loop L1
quit:
ret
check_distance ENDP

check_substr PROC, sp_word: ptr byte, text: ptr byte
local len_sp: byte
local text_len:dword
mov len_sp,0

invoke str_length, text
inc eax
mov text_len,eax

mov edi,sp_word
mov al,13
LQ:
	scasb
	jz next
	inc len_sp
	jmp LQ
	
next:

mov edx,0
mov edi,sp_word
mov esi,text
sub len_sp,1


mov ecx,text_len
L1:
push ecx
mov al,[edi]
cmp al,[esi]
jnz out1
mov cl,len_sp
movzx ecx,cl
mov ebx,1
L2:
mov al,[edi+ebx]
cmp al,[esi+ebx]
mov al,[esi+ebx]
jne out1
inc ebx
dec ecx
jecxz found
jmp L2
out1:
inc esi
pop ecx
loop L1
jmp e
found:
mov ebx,offset distance
mov al,type distance
mov cl,fregencounter
mul cl
add bl,al
mov dword ptr [ebx],esi
inc fregencounter
inc spam_score

pop ecx
jecxz e
push ecx
jmp out1
e:
ret
check_substr ENDP

check_spam PROC uses ecx

local spword[40]: byte 


mov ecx,40
lea edi,spword
mov al,0
rep stosb
mov edi,offset spam_words
cld
mov ebx,len
add edi,ebx
lea esi,spword
mov al,13
MyLoop:
mov bl,[edi]
mov [esi],bl
inc esi
inc len
scasb
jz quit
jmp MyLoop

quit:
inc len
mov edx,0
invoke check_substr, addr spword, addr subject
invoke check_substr, addr spword, addr content
mov al,[edi]
sub al,32
mov [edi],al
invoke check_substr, addr spword, addr content
;mov edx,offset subject 
;call writestring

ret
check_spam ENDP

get_spam_words PROC uses ecx

mov edx,OFFSET filename2
call OpenInputFile
mov fileHandle,eax
; Check for errors.
cmp eax,INVALID_HANDLE_VALUE ; error opening file?
jne file_ok ; no: skip
jmp quit ; and quit
file_ok:
; Read the file into a buffer.
mov edx,OFFSET spam_words
mov ecx,lengthof spam_words
call ReadFromFile
jnc check_words_size ; error reading?
call WriteWindowsMsg
jmp close_file
check_words_size:
cmp eax,lengthof spam_words ; buffer large enough?
jb buf_size_ok ; yes
jmp quit ; and quit
buf_size_ok:
mov spam_words[eax],0 ; insert null terminator
;call WriteDec ; display file size
;call Crlf
; Display the buffer.
;mov edx,OFFSET spam_words ; display the buffer
;call WriteString
;call Crlf
close_file:
mov eax,fileHandle
call CloseFile

quit:
;mov edx,offset spam_words
;call writestring
;jmp quit
ret

get_spam_words ENDP 


get_separate PROC, location: ptr byte

mov edi,offset buffer
mov ebx,len
add edi,ebx
mov esi,location
cld
mov al,10
MyLoop:
mov bl,[edi]
mov [esi],bl
inc esi
inc len
scasb
jz quit

jmp MyLoop

quit:

;mov edx,location
;call writestring
;call crlf

ret
get_separate ENDP

get_content PROC, contentx:ptr byte

mov edi,offset buffer
mov ebx,len
add edi,ebx
mov esi,contentx

cld
mov al,'*'
MyLoop:
mov bl,[edi]
mov [esi],bl
inc esi
inc len
scasb
jz quit
jmp MyLoop

quit:

mov al,' '
mov [esi-1],al
;mov edx,contentx
;call writestring
;call crlf
ret
get_content ENDP

get_email PROC 
local input:byte
mov esi,offset filename
mov edx, offset msg
call writestring
call readdec
mov input,al
cmp al,10
jc skip
mov bl,10
cbw
div bl
add [filename+5],al
mov bl,10
mul bl
sub input,al
mov bl,input
add [filename+6],bl

jmp e
skip:
add [filename+6],al
e:
ret
get_email ENDP

get_num_of_words PROC, text: ptr byte, leng: dword

mov edi,text
mov ecx,leng
mov al,' '
L1:
	scasb
	jnz skip
	inc word_count
	skip:
	loop L1
ret
get_num_of_words ENDP

finalize_spam PROC, spamscore: byte, wordcount: word

call crlf
mov edx, OFFSET space
call writestring
call crlf
mov edx, OFFSET space
call writestring
mov edx, offset sps6
call writestring
call crlf

;mov eax,0
;mov al,spamscore
;call writedec

mov ax,word_count
cmp ax,50
jc thirty
cmp ax,100
jc twenty

mov bx,10
cwd
div bx
mov bx,1
mul bx
cmp al,spamscore
jnc not_spam
jmp next


twenty:
mov bx,10
cwd
div bx
mov bx,2
mul bx
cmp al,spamscore
jnc not_spam
jmp next

thirty:
mov bx,10
cwd
div bx
mov bx,3
mul bx
cmp al,spamscore
jnc not_spam


next:
call crlf
mov edx, OFFSET space
call writestring
mov edx, OFFSET line
call writestring
call crlf
mov edx, OFFSET space
call writestring
mov edx,offset spam_msg
call writestring
mov al,spamscore
movzx eax,al
call writedec
call crlf
mov edx, OFFSET space
call writestring
mov edx, OFFSET line
call writestring
jmp skip

not_spam:
call crlf
call crlf
mov edx, OFFSET space
call writestring
mov edx, OFFSET line
call writestring
call crlf
mov edx, OFFSET space
call writestring
mov edx, offset not_spam_msg
call writestring
call crlf
mov edx, OFFSET space
call writestring
mov edx, OFFSET line
call writestring
call crlf
skip:



ret
finalize_spam ENDP

main PROC
mov eax, 11
;call SetTextColor

mov eax,0
mov edx,0
call firstpage
call clrscr
call mainpage
cmp authorize,1
jnz last
call crlf
call get_email

call get_data
invoke get_separate, addr subject

invoke get_separate, addr datetime
invoke get_separate, addr sender
invoke get_separate, addr receiver
call verify_email

invoke get_content, addr content
mov len,0

call get_spam_words

invoke str_length, addr spam_words
mov str_len,eax
invoke get_num_of_words, addr spam_words,str_len
mov cx,word_count
movzx ecx,cx
L1:
	call check_spam
	loop L1
invoke Quicksort, addr distance,0,fregencounter-1

invoke check_distance, addr distance

invoke str_length, addr content
mov str_len,eax
invoke get_num_of_words, addr content,str_len
invoke finalize_spam, spam_score, word_count

call crlf
last:


exit
main ENDP


verify_email PROC
local leng:byte,count:dword

local domain_receiver[20]:byte
local domain_sender[20]:byte


mov count,0 
mov ecx,lengthof sender
mov esi, OFFSET sender


L1:
mov al,[esi]
inc count
cmp al,'@'
jz point_s
inc esi
Loop L1

point_s:

mov edi, OFFSET sender
add edi,count
mov bl,leng
movzx ebx,bl
add edi,ebx
lea esi,domain_sender
cld
mov al,10
MyLoopy:
mov bl,[edi]
mov [esi],bl
inc esi
inc leng
scasb
jz en
jmp MyLoopy

en:

mov leng,0
mov count,0
mov ecx,lengthof receiver
mov esi, OFFSET receiver 

L2:
mov al,[esi]
inc count
cmp al,'@'
jz point_r
inc esi
Loop L2

point_r:

mov edi, OFFSET receiver
add edi,count
mov bl,leng
movzx ebx,bl
add edi,ebx
lea esi,domain_receiver
cld
mov al,10
MyLoop:
mov bl,[edi]
mov [esi],bl
inc esi
inc leng
scasb
jz rec
jmp MyLoop

rec:

lea edi,domain_receiver
lea esi, domain_sender
mov cl,leng
movzx ecx,cl
mu:
mov al,[esi]
cmp al,[edi]
jnz ex
inc esi
inc edi
loop mu

strings_equal:
mov edx, OFFSET space
call writestring
mov edx,offset status
call WriteString
call crlf
jmp lala

ex:
call crlf
mov edx, OFFSET space
call writestring
mov edx,offset status_rej
call WriteString
add spam_score,5
call crlf
mov edx, OFFSET space
call writestring
mov edx,offset sps1
call WriteString
call crlf




lala:
ret
verify_email ENDP


get_data PROC
mov edx,OFFSET filename
call OpenInputFile
mov fileHandle,eax
; Check for errors.
cmp eax,INVALID_HANDLE_VALUE ; error opening file?
jne file_ok ; no: skip
jmp quit ; and quit
file_ok:
; Read the file into a buffer.
mov edx,OFFSET buffer
mov ecx,BUFFER_SIZE
call ReadFromFile
jnc check_buffer_size ; error reading?
call WriteWindowsMsg
jmp close_file
check_buffer_size:
cmp eax,BUFFER_SIZE ; buffer large enough?
jb buf_size_ok ; yes
jmp quit ; and quit
buf_size_ok:
mov buffer[eax],0 ; insert null terminator
;call WriteDec ; display file size
;call Crlf
; Display the buffer.
mov edx,OFFSET buffer ; display the buffer
;call WriteString
;call Crlf
close_file:
mov eax,fileHandle
call CloseFile
quit:
ret
get_data ENDP


partition proc,A:PTR dword,lo: dword,hi: dword
Local  pivot : dword,i :  dword,j :dword

mov esi,[A]
imul ebx,hi,type A
add esi,ebx
mov eax,[esi]
mov pivot,eax
;call writedec

mov eax,lo
dec eax
mov i,eax
;call writeint
mov eax,lo
mov j,eax
;call writeint
FORHI:
push esi
push ebx
mov esi,[A]
imul ebx,j,type A
add esi,ebx
pop ebx
push eax
mov eax,[esi]
cmp eax,pivot
ja L1
inc i
mov edi,[A]
imul ebx,i,type A
add edi,ebx
INVOKE swap,esi,edi
L1:
pop eax
pop esi
inc j
mov eax,j
cmp eax,hi
jb FORHI
inc i
push esi
mov esi,[A]
push ebx
imul ebx,i,type A
add esi,ebx
pop ebx
push edi
mov edi,[A]
push ebx
imul ebx,hi,type A
add edi,ebx
pop ebx
INVOKE swap,esi,edi
pop edi
pop esi

mov eax,i


ret
partition endp

Quicksort proc,A: PTR dword,lo: dword,hi: dword
local pi: dword
mov eax,0
mov eax,lo
cmp eax,hi
jae L1

INVOKE partition,A,lo,hi
mov pi,eax

push pi
inc pi
INVOKE Quicksort,A,pi,hi
pop pi
push pi
dec pi
INVOKE Quicksort,A,lo,pi
pop pi


L1:
ret 
Quicksort endp

swap proc,val1:PTR dword,val2:PTR dword
mov eax,0
mov esi,val1
mov edi,val2
mov eax,[esi]
xchg eax,[edi]
mov [esi],eax
ret
swap endp


decryption PROC, passfile: ptr byte

mov esi,passfile
mov ecx,5
L2:
mov al,[esi]
add al,6
cmp al,123
jc skip
sub al,26
skip:
mov [esi],al
inc esi
Loop L2

call crlf

ret
decryption ENDP

mainpage proc
;call crlf
mov edx, OFFSET space
call writestring
mov edx, OFFSET line
call writestring
mov edx, OFFSET space
call writestring
mov edx, OFFSET space
call writestring
mov edx, OFFSET text1
call writestring
call crlf
mov edx, OFFSET space
call writestring
mov edx, OFFSET line
call writestring
call crlf

call crlf
mov edx, OFFSET space
call writestring
ret
mainpage ENDP

FirstPage Proc
local leng:byte
local input[20]: byte
local email_user [20]: byte
local email_file [20]: byte
local pass_file [20]: byte
local pass_user [20]: byte


call crlf
call crlf
call crlf
call crlf
call crlf
call crlf
mov edx, OFFSET space
call writestring
mov edx, OFFSET line
call writestring

call crlf
mov edx, OFFSET space
call writestring
mov edx, OFFSET text1
call writestring
call crlf
mov edx, OFFSET space
call writestring
mov edx, OFFSET line
call writestring
call crlf

call crlf
mov edx, OFFSET space
call writestring

mov edx,OFFSET m2
call writestring
call crlf
call crlf
mov edx,OFFSET msg_add
call writestring


mov edx,OFFSET userFile
call OpenInputFile
mov fileHandle2,eax
cmp eax,INVALID_HANDLE_VALUE ; error opening file?
jne file_ok ; no: skip
jmp quit ; and quit
file_ok:

lea edx,email_file
mov ecx,20
call ReadFromFile
quit:
push eax
;mov edx,OFFSET email_user
;call writestring

mov ecx,0
mov al,10
lea edi, email_file
lea esi, email_user
L1:
	mov bl,[edi]
	mov [esi],bl
	scasb
	jz outer
	inc esi
	inc ecx
	jmp L1
outer:

pop eax

lea esi, pass_file
sub eax,ecx
mov ecx,eax
L2:
	mov bl,[edi]
	mov [esi],bl
	inc esi
	inc edi
	loop L2

mov ecx,lengthof input
lea edx,input
call readstring


lea esi, input
lea edi, email_user
invoke str_length, addr email_user
mov ecx,eax
sub ecx,2
Lx:
mov al,[esi]
cmp al,[edi]
jnz wrong
inc esi
inc edi
Loop Lx


correct:
		mov edx,OFFSET email_match
		call writestring
		call crlf
		call crlf
		mov edx,OFFSET msg_pass
		call writestring


		lea edx, pass_user
		mov ecx,Lengthof pass_user
		call readstring

		invoke decryption,addr pass_file

		
		lea esi, pass_file
		lea edi, pass_user
		
		mov eax,[esi]
		mov ebx,[edi]
		cmp eax,ebx
		jz match
		jnz wrong


		match:
		mov edx,OFFSET access
		call writestring
		mov authorize,1
		jmp endproc
wrong:
		mov edx,OFFSET unmatch
		call writestring
		call Crlf
endproc:


ret
FirstPage ENDP


END main