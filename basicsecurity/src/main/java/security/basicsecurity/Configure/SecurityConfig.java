package security.basicsecurity.Configure;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

@Configuration // 설정파일 이므로 Configuration 어노테이션 설정
@EnableWebSecurity // 스프링 시큘리티의 동작과 관련된 클래스 파일들을 임포트 시켜 동작시키는 어노테이션
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    // 스프링 시큐리티의 웹 보안 기능을 초기화 및 설정하는 WebSecurityConfigurerAdapter 클래스
    // 세부적 보안기능을 설정할수 있는 API 인 HttpSecurity를 제공한다.


    UserDetailsService userDetailsService;
    @Autowired
    public void setUserDetailsService(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @Override // 웹 보안 기능을 설정하는 configure(HttpSecurity) 메서드를 재정의 하여 설정, 재정의 안하면 기본 설정으로 동작
    protected void configure(HttpSecurity http) throws Exception {
        http
                // 권한 인가는 Top-Down 방식으로 이루어 진다 그래서 아래로 갈수록 넓은 범위의 인가조건으로 정렬해야 한다.
                //.antMatcher() // 조건에 맞는 요청만 보안 검사를 실시
                .authorizeRequests() // 권한검사 api 메서드
                .antMatchers("/user").hasRole("USER")
                // 조건에 맞는 패턴에 대하여 특정 권한을 가진 계정만 인가함
                .antMatchers("/admin/pay").hasRole("ADMIN") // 경로와 권한으로 인가
                .antMatchers("/admin/**").access("hasRole('ADMIN') or hasRole('SYS')") // spel
                // /admin 을 포함한 모든 하위 조건에 대하여 조건식으로 인가함
                .anyRequest().authenticated()
        .and().formLogin() // 인증방식은 폼 로그인
        ;
    }

    @Override // 사용자의 생성, 권한부여 설정 기능 제공
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication().withUser("user").password("{noop}1234").roles("USER");
        auth.inMemoryAuthentication().withUser("sys").password("{noop}1234").roles("SYS","ADMIN","USER");
        auth.inMemoryAuthentication().withUser("admin").password("{noop}1234").roles("ADMIN","USER");
        // 메모리 방식 계정 추가, 생성되는 수의 제한 없음
        // 계정명
        // 패스워드, prefix 형태로 암호화 정보를 명시 {noop}은 평문
        // 권한 설정
    }

    private void authenticationApi(HttpSecurity http) throws Exception {
        http // 인가정책 설정 - 기능에 대하여 접근이 가능한지를 판별
                .authorizeRequests() // 요청에 대한 인가 권한검사 (권한 검사 실시) ( 동작조건 )
                .anyRequest() // 모든 요청에 대하여 실행 ( 필터조건 )
                .authenticated() // 인증을 받아야함 ( 필요조건 )
//----------------------------------------------------------------------------------------------------------------------
        // LoginFilter
        .and() // 인증정책 설정 - 기능에 접근이 가능한지를 검증, and() 메서드 - HttpSecurity 인스턴스에 대하여 체이닝 방식으로 여러가지지 설정 가능
               .formLogin() //  인증정책을 폼 로그인 으로 설정
                //.loginPage("/loginPage") // 사용자 정의 로그인 페이지 미설정시 스프링 기본 로그인 페이지 제공
                .defaultSuccessUrl("/") // 로그인 성공페이지
                .failureUrl("/login") // 실패 페이지
                .usernameParameter("userId")  // 아이디 파라미터의 이름을 지정 기본은 username UI설정과 같아야함
                .passwordParameter("passwd") // 패스워드 파라미터의 이름을 지정 기본은 password UI설정과 같아야함
                .loginProcessingUrl("/login_proc") /// form 로그인 동작 url 을 매핑 가능 기본은 login UI 설정과 같아야함
                .successHandler(new AuthenticationSuccessHandler() {
                    @Override // 인증 성공 핸들러를 익명 클래스로 정의, 인증 성공시 동작, defaultSuccessUrl() 메서드보다 세부 설정가능
                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                                        Authentication authentication)
                            throws IOException, ServletException {
                        System.out.println("authentication = " + authentication.getName()); // 인증정보의 이름을 출력
                        response.sendRedirect("/"); // 지정한 url 로 리다이렉트
                    }
                }) // 로그인 성공시 설정된 핸들러 호출
                .failureHandler(new AuthenticationFailureHandler() {
                    @Override // 인증 실패 핸들러를 정의, failureUrl() 메서드보다  서부적인 설정이 가능함
                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                                        AuthenticationException e)
                            throws IOException, ServletException {
                        System.out.println("exception = " + e.getMessage()); // 예외 메세지 ( 인증 실패 ) 출력
                        response.sendRedirect("/login"); // 실패하면 로그인 페이지로 리다이렉트
                    }
                }) // 로그인 실패시 설정된 핸들러 호출
                .permitAll() // 로그인 페이지에 대해서는 모든 사용자가 접근이 가능하도록 허용함
//----------------------------------------------------------------------------------------------------------------------
        // LogoutFilter
        .and()
                .logout() // 로그아웃 필터 설정용 메서드
                .logoutUrl("/logout") // 로그아웃이 호출될 url 패턴, 스프링 시큐리티는 기본적으로는 Post 방식으로만 가능
                .logoutSuccessUrl("/login") // 로그아웃이 성공하면 이동할 페이지
                .addLogoutHandler(new LogoutHandler() {
                    @Override // 로그아웃 핸들러의 익명 클래스 정의
                    public void logout(HttpServletRequest request, HttpServletResponse response,
                                       Authentication authentication) {
                        HttpSession session = request.getSession(); // 리퀘스트 서블렛에서 세션을 받음
                        session.invalidate(); // 세션을 비활성화
                    }
                }) // 로그아웃을 처리할 핸들러, 기본 핸들러 있음, 직접 정의 가능
                .logoutSuccessHandler(new LogoutSuccessHandler() {
                    @Override // 로그아웃 핸들러 정의, logoutSuccessUrl() 보다 세부적인 기능정의 가능하다
                    public void onLogoutSuccess(HttpServletRequest request,
                                                HttpServletResponse response, Authentication authentication)
                            throws IOException, ServletException {
                        response.sendRedirect("/login");
                    }
                }) // 로그아웃 성공시에 호출될 핸들러
                .deleteCookies("remember-me") // 발급된 쿠키명을 변수로 넣어서 로그아웃시 발급된 쿠키를 삭제

//----------------------------------------------------------------------------------------------------------------------
        .and()
                .rememberMe() // RememberMe - 인증 세션이 만료, 종료된 이후에도 인증 정보를 쿠키로 남기며 바로 인증받을수 있다.
                .rememberMeParameter("remember") // UI 에서 전달되는 RememberMe 파라미터 name 을 설정가능
                .tokenValiditySeconds(3600) // 발급된 인증서, 쿠키의 유효시간을 초단위 지정, 기본은 14일
                .userDetailsService(userDetailsService) // remember-Me 의 인증정보와 대조하기 위해 계정들을 조회하는 기능 수행 (필수)
                //.alwaysRemember(true) // rememberMe 기능을 언제나 활성화 시킨다
//----------------------------------------------------------------------------------------------------------------------
        .and()
                .sessionManagement() // 사큐리티 세션 관리를 위한 api
                .sessionCreationPolicy( // 세션 생성전략의 설정
                        //SessionCreationPolicy.ALWAYS // 시큐리티가 HttpSession 을 항상 행성
                        SessionCreationPolicy.IF_REQUIRED // 시큐리티가 세션이 필요할 때만 생성, 기본값
                        //SessionCreationPolicy.NEVER // 시큐리티가 세션을 생성하지 않음 하지만 이미 있다면 사용
                        //SessionCreationPolicy.STATELESS
                        // 시큐리티가 세션을 생성하지도, 존재하는 걸 사용하지도 않음 JWT 같은 방식에서 사용
                        // 정확히는 스프링 시큐리티가 인증방식에 세션쿠키 방식을 사용하지 않음
                )
                .sessionFixation() // 고정세션 공격에 대한 방어전략 제공
                .changeSessionId() // 기본값, 이전새션을 재사용 가능하며 세션에 새로운 세션 ID를 부여
                //.migrateSession() // 서블릿 3.1 이전 방어용 전략
                //.newSession() // 아예 새로운 새션을 지급하여 세션을 교체, 이전세션은 폐기
                //.none() // 권한 인증을 하여도 세션이 변하지 않음, 공격자가 해당 세션 ID를 안다면 침투 가능
                .invalidSessionUrl("/") // 세션이 유효하지 않은 경우 redirect 시킬 url 을 설정, expiredUrl() 보다 우선
                .maximumSessions(1) // 계정이 동시에 가질수 있는 최대 세션의 수, -1은 제한없음
                .maxSessionsPreventsLogin(false)
                // 세션 멕시멈이 초과시 대응 전략, default 는 false - 인증 차단, true - 기존 인증 해지
                .expiredUrl("/login") // 세션 만료시 이동 URL 지정
        ;
    }
}
