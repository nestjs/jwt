import { Module } from '@nestjs/common';
import { ConfigurableModuleClass } from './jwt.module-definition';
import { JwtService } from './jwt.service';

@Module({
  providers: [JwtService],
  exports: [JwtService]
})
export class JwtModule extends ConfigurableModuleClass {}
