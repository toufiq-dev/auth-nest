import {
  ConflictException,
  Inject,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from 'src/users/entities/user.entity';
import { Repository } from 'typeorm';
import { HashingService } from '../hashing/hashing.service';
import { SignUpDto } from './dto/sign-up.dto';
import { PG_UNIQUE_VIOLATION_CODE } from 'src/common/constants/error-codes.constants';
import { SignInDto } from './dto/sign-in.dto';

@Injectable()
export class AuthenticationService {
  constructor(
    @InjectRepository(User) private readonly userRepository: Repository<User>,
    private readonly hashingService: HashingService,
  ) {}

  async signUp(signupDto: SignUpDto) {
    try {
      const user = new User();
      user.email = signupDto.email;
      user.password = await this.hashingService.hash(signupDto.password);

      await this.userRepository.save(user);
    } catch (error) {
      if (error.code === PG_UNIQUE_VIOLATION_CODE) {
        throw new ConflictException();
      }

      throw error;
    }
  }

  async signIn(signInDto: SignInDto) {
    const { email, password } = signInDto;
    const user = await this.userRepository.findOneBy({
      email,
    });

    if (!user) throw new UnauthorizedException('User does not match');

    const isEqual = await this.hashingService.compare(password, user.password);

    if (!isEqual) throw new UnauthorizedException('Password does not match');

    return true;
  }
}
