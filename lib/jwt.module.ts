import { DynamicModule, Module, Provider } from '@nestjs/common';
import {
  JwtModuleAsyncOptions,
  JwtModuleOptions,
  JwtOptionsFactory
} from './interfaces/jwt-module-options.interface';
import { JWT_MODULE_OPTIONS } from './jwt.constants';
import { createJwtProvider } from './jwt.providers';
import { JwtService } from './jwt.service';

@Module({
  providers: [JwtService],
  exports: [JwtService]
})
export class JwtModule {
  static register(options: JwtModuleOptions): DynamicModule {
    return {
      module: JwtModule,
      global: options.global,
      providers: createJwtProvider(options)
    };
  }

  static registerAsync(options: JwtModuleAsyncOptions): DynamicModule {
    return {
      module: JwtModule,
      global: options.global,
      imports: options.imports || [],
      providers: [
        ...this.createAsyncProviders(options),
        ...(options.extraProviders ?? [])
      ]
    };
  }

  private static createAsyncProviders(
    options: JwtModuleAsyncOptions
  ): Provider[] {
    if (options.useExisting || options.useFactory) {
      return [this.createAsyncOptionsProvider(options)];
    }
    return [
      this.createAsyncOptionsProvider(options),
      {
        provide: options.useClass,
        useClass: options.useClass
      }
    ];
  }

  private static createAsyncOptionsProvider(
    options: JwtModuleAsyncOptions
  ): Provider {
    if (options.useFactory) {
      return {
        provide: JWT_MODULE_OPTIONS,
        useFactory: options.useFactory,
        inject: options.inject || []
      };
    }
    return {
      provide: JWT_MODULE_OPTIONS,
      useFactory: async (optionsFactory: JwtOptionsFactory) =>
        await optionsFactory.createJwtOptions(),
      inject: [options.useExisting || options.useClass]
    };
  }
}
