import { IsOptional, IsString, IsEmail } from 'class-validator';

export class LoginDto {
  @IsOptional()
  @IsString()
  readonly userId?: string;

  @IsOptional()
  @IsString()
  readonly mobile?: string;

  @IsOptional()
  @IsEmail()
  readonly email?: string;

  @IsOptional()
  @IsString()
  readonly password?: string;

  @IsOptional()
  @IsString()
  readonly confirm_password?: string;
}
