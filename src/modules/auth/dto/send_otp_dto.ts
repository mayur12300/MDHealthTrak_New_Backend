import { IsOptional, IsString, IsEmail, ValidateIf } from 'class-validator';

export class SendOtpDto {
  @IsOptional()
  @IsString()
  readonly userId?: string;

  @ValidateIf((o) => !o.email)
  @IsString()
  readonly mobile?: string;

  @ValidateIf((o) => !o.mobile)
  @IsEmail()
  readonly email?: string;

  @IsOptional()
  @IsString()
  readonly country_code?: string; // +91, +1, etc.
}

// import { IsOptional, IsString, IsEmail, IsNotEmpty } from 'class-validator';

// export class SendOtpDto {
//   @IsOptional()
//   @IsString()
//   readonly userId?: string;

//   @IsOptional()
//   @IsString()
//   readonly mobile?: string;

//   @IsOptional()
//   @IsString()
//   readonly country_code?: string; // e.g., +91, +1, +971

//   @IsOptional()
//   @IsEmail()
//   readonly email?: string;
// }

// import {
//   IsOptional,
//   IsString,
//   IsEmail,
//   IsNotEmpty,
//   Matches,
//   ValidateIf,
// } from 'class-validator';

// export class SendOtpDto {
//   @IsOptional()
//   @IsString()
//   readonly userId?: string;

//   // ✅ Validate mobile only if email is NOT present
//   @ValidateIf(o => !o.email)
//   @IsNotEmpty({ message: 'Mobile is required if email is not provided' })
//   @Matches(/^[0-9]{6,15}$/, {
//     message: 'Mobile number must contain only digits (6–15)',
//   })
//   readonly mobile?: string;

//   // ✅ Country code like +91, +1, +971
//   @ValidateIf(o => !!o.mobile)
//   @IsNotEmpty()
//   @Matches(/^\+\d{1,4}$/, {
//     message: 'Invalid country code format (e.g. +91)',
//   })
//   readonly country_code?: string;

//   // ✅ Validate email only if mobile is NOT present
//   @ValidateIf(o => !o.mobile)
//   @IsNotEmpty({ message: 'Email is required if mobile is not provided' })
//   @IsEmail({}, { message: 'Invalid email address' })
//   readonly email?: string;
// }
