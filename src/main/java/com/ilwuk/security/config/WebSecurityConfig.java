package com.ilwuk.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

/**
 * @author Administrator
 * @version 1.0
 **/
@Configuration
@EnableGlobalMethodSecurity(securedEnabled = true,prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

//    //定义用户信息服务（查询用户信息）
//
//    @Bean
//    public UserDetailsService userDetailsService(){
//        InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
//        manager.createUser(User.withUsername("zhangsan").password("123").authorities("p1").build());
//        manager.createUser(User.withUsername("lisi").password("456").authorities("p2").build());
//        return manager;
//    }



   // 密码编码器
   // @Bean
  //  public PasswordEncoder passwordEncoder(){
      //  return NoOpPasswordEncoder.getInstance();
   // }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    //安全拦截机制（最重要）
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
                .authorizeRequests()//这个检验从上到下，一直要注意顺序，
                .antMatchers("/r/r1").hasAuthority("p2")
                .antMatchers("/r/r2").hasAuthority("p3")
                .antMatchers("/r/**")
                .authenticated()
                .anyRequest().permitAll()
                .and() .formLogin().successForwardUrl("/login-success")
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED);

    }
}





