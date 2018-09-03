extern crate rand;

use std::io;
use std::cmp::Ordering;
use rand::Rng;


fn main()
{
	let mut a1=0xfff;
	let mut a2=0x100;
	let buf="world!";
	println!("hello {}",buf);
	println!("a1: {}",a1);
	
	a1=0x100;
	println!("then a1: {}",a1);
	
	let mut string=String()::new();
	io::stdin().read_line(&mut string)
		.expect("read failed.");

	let sec_num=rand::thread_rng().gen_range(1,101);
	println!("the sec num is :{}",sec_num);
	println!("your input:{}",string);

	match string.cmp(&sec_num){
	  Ordering::Less   =>  println!("Too small!"),
	  Ordering::Greate =>  println!("Too big!"),
	  Ordering::Equal  =>  println!("You got it!"),

	}

	

}
