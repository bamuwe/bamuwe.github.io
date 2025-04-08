<?php

function calculate_seed_value($email, $constant_value)
{
    $email_length = strlen($email);
    $email_hex = hexdec(substr($email, 0, 8));
    $seed_value = hexdec($email_length + $constant_value + $email_hex);

    return $seed_value;
}

function generate_token($email, $constant_value)
{
    $seed_value = calculate_seed_value($email, $constant_value);
    mt_srand($seed_value);
    $random = mt_rand();
    $invite_code = base64_encode($random);

    return $invite_code;
}


$email = "hello@fake.thm";
$token = generate_token($email, 99999);
print $token

    ?>