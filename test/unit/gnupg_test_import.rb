#!/usr/bin/env ruby

def other_random_test(num=$tst.to_i)
	r = num
	r = rand (1..1024) while r == num
	return r
end

def testname(num=$tst.to_i)
	%Q{Ed25519_gnupg_t#{num}}
end

def first_pass(k,v)
	case k
	when 'TST'
		$tst=v
	when 'SIG'
		$signatures[$tst.to_i]=v
	end
end

def parse(k,v)
	str = ""
	
	case k
	when 'TST'
		$tst=v
		str = "\n\n# gnupg t-ed25519.inp test data sets -- TEST #{$tst}\n\n"
	when 'SK'
		str = "PrivateKey = #{testname}\n"
		str << `./hex2pem.sh priv "#{v}"` << "\n"
	when 'PK'
		str = "PublicKey = #{testname}-PUBLIC\n"
		str << `./hex2pem.sh pub "#{v}"` << "\n"
		str << "\n"
		str << "PrivPubKeyPair = #{testname}:#{testname}-PUBLIC\n\n"
	when 'MSG'
		$msg=v
		$msg=%Q{""} if $msg.empty?
	when 'SIG'
		str =  "Sign = #{testname}\n"
		str << "Input = #{$msg}\n"
		str << "Output = #{v}\n"
		str << "\n"
		str << "Verify = #{testname}-PUBLIC\n"
		str << "Input = #{$msg}\n"
		str << "Output = #{v}\n"
		str << "\n"
		str << "# Negative checks\n"
		str << "Sign = #{testname}\n"
		str << "Input = #{$msg}\n"
		str << "Output = #{$signatures[other_random_test]}\n"
		str << "Result = KEYOP_MISMATCH\n"
		str << "\n"
		str << "Verify = #{testname}-PUBLIC\n"
		str << "Input = #{$msg}\n"
		str << "Output = #{$signatures[other_random_test]}\n"
		str << "Result = VERIFY_ERROR\n"
		str << "\n"
	else
		STDERR.puts "Unsupported keyword: \"#{k}\" => \"#{v}\""
		return nil
	end
	puts str

	[k,v]
end

$signatures = []
#f = File::open("t-ed25519.inp", "rb")
f = ARGF
f.readlines.reject{|l| (l =~ /^#/) || l.strip.empty? }.map do |l|
	k,v = l.split(?:).map{|i| i.strip}
end.each do |k,v|
	first_pass(k,v)
end.map do |k,v|
	parse(k,v)
end

puts "# Negative keypairs checks\n"
(1..1024).each do |n|
	str = "PrivPubKeyPair = #{testname n}:#{testname other_random_test(n)}-PUBLIC\n"
	str << "Result = KEYPAIR_MISMATCH\n"
	puts str
end
