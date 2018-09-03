fn main()
{
	let _n=5;

	let x = 5;
	
	let _y = if x == 5 {
	    10
	} else {
	    15
	};

	match _n {
	0 | 5 => println!("it is 5!"),
	6 | 10 => println!("it is 10!"),
	_ => println!("what?"),

	}

	println!("hello world!\n");

}
