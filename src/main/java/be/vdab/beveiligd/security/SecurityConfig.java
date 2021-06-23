package be.vdab.beveiligd.security;

import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

import javax.sql.DataSource;

@EnableWebSecurity
class SecurityConfig extends WebSecurityConfigurerAdapter {
    private static final String MANAGER = "manager";
    private static final String HELPDESKMEDEWERKER = "helpdeskmedewerker";
    private static final String MAGAZIJNIER = "magazijnier";
    private final DataSource dataSource;

    SecurityConfig(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        auth.inMemoryAuthentication()
//                .withUser("joe").password("{noop}theboss").authorities(MANAGER)
//                .and()
//                .withUser("averell").password("{noop}hungry").authorities(HELPDESKMEDEWERKER, MAGAZIJNIER);
        auth.jdbcAuthentication().dataSource(dataSource)
                .usersByUsernameQuery(
                        "select naam as username,paswoord as paswoord,actief as enabled" +
                                " from gebruikers where naam = ?")
                .authoritiesByUsernameQuery("select g.naam as username, r.naam as authorities " +
                        "from gebruikers g " +
                        "inner join gebruikersrollen gr " +
                        "on g.id = gr.gebruikerId " +
                        "inner join rollen r " +
                        "on gr.rolId = r.id " +
                        "where g.naam = ?");
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring()
                .mvcMatchers("/images/**")
                .mvcMatchers("/css/**")
                .mvcMatchers("/js/**");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.formLogin(login->login.loginPage("/login"));
        http.authorizeRequests(requests -> requests
                .mvcMatchers("/offertes/**").hasAuthority(MANAGER)
                .mvcMatchers("/werknemers/**").hasAnyAuthority(MAGAZIJNIER,HELPDESKMEDEWERKER)
                .mvcMatchers("/","/login").permitAll()
                .mvcMatchers("/**").authenticated());
        http.logout(logout -> logout.logoutSuccessUrl("/"));
    }

}
