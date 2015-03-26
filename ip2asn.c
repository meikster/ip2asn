#define	_GNU_SOURCE	1
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gmp.h>
#include <arpa/inet.h>
#include <bsd/stdio.h>

typedef struct	s_ip
{
  int		version;
  unsigned int	v4_ip;
  mpz_t		v6_ip;
} t_ip;

typedef struct	s_entry
{
  int	lower;
  int	upper;
  char *name;
} t_entry;

void	usage(char *progname)
{
  printf("Usage:\n\t%s <IP.v4.Addr.ess>\n"			\
	 "\t%s <ip:v6:ad:re:ss>\n\n", progname, progname);
  exit(-1);
}

void	i2a_print_results(char *orig_ip, char *asn_str)
{
  if (!asn_str)
    printf("[-] No AS number has been found for IP address [%s]\n", orig_ip);
  else
    printf("[+] %s belongs to %s\n", orig_ip, asn_str);  
}

int	i2a_ipv4_getentry(FILE *f, t_entry *entry)
{
  char		*line;
  size_t	line_len;

  if (feof(f))
    return(0);
  line = fgetln(f, &line_len);
  if (!line)
    return(0);
  line[line_len - 1] = '\0';
  entry->lower = atoi(strtok(line, ","));
  entry->upper = atoi(strtok(NULL, ","));
  entry->name = strtok(NULL, ",");
  return(1);
}

char	*i2a_ipv6_getasn(mpz_t *ip_int)
{
  FILE		*f;
  mpz_t	low, high;
  int	cmp1, cmp2, c;
  char	*junk;
  char	*line;
  char	*line_cp;
  size_t	line_len;
  char	*asn;

  
  f = fopen("GeoIPASNum2v6.csv", "r");
  if (!f)
    {
      printf("[-] No IPv6 ip2asn database :(\n");
      return(0);
    }
  while (!feof(f))
    {
      if (!(line = fgetln(f, &line_len)))
	break;
      line_cp = strndup(line, strlen(line));
      c = strlen(line_cp);
      line_cp[c - 1] = '\0'; /* remove the \n */
      junk = strtok(line_cp, ",");
      junk = strtok(NULL, ",");

      /* comparaison ip >= debut range && ip <= fin range */
      junk = strtok(NULL, ",");
      mpz_init_set_str(low, junk, 10);
      junk = strtok(NULL, ",");
      mpz_init_set_str(high, junk, 10);
      cmp1 = mpz_cmp(*ip_int, low);
      cmp2 = mpz_cmp(*ip_int, high);
      if (cmp1 >= 0 && cmp2 <= 0)
	{
	  junk = strtok(NULL, ",");
	  asn = strndup(junk, strlen(junk));
	  mpz_clear(low);
	  mpz_clear(high);
	  free(line_cp);
	  fclose(f);
	  return(asn);
	}
      free(line_cp);
      mpz_clear(low);
      mpz_clear(high);
    }
  fclose(f);
  
  return(NULL);
}

char	*i2a_ipv4_getasn(int ip)
{
  FILE		*f;
  t_entry	data;
  char		*asn;

  if (!(f = fopen("GeoIPASNum2.csv", "r")))
    return(NULL);
  while (i2a_ipv4_getentry(f, &data) != 0)
    {
      if (ip >= data.lower && ip <= data.upper)
	{
	  asn = strndup(data.name, strlen(data.name));
	  fclose(f);
	  return(asn);
	}
    }
  fclose(f);
  return(NULL);
}

int	i2a_ipv4_getint(unsigned int *long_ip, char *ip_str)
{
  *long_ip = ntohl(inet_addr(ip_str));
  return(0);
}

int	i2a_ipv6_getint(mpz_t *ip_int, char *ip_str)
{
  unsigned char buf[sizeof(struct in6_addr)];
  mpz_t	result, left, right, byte, mask;
  int	i;

  inet_pton(AF_INET6, ip_str, buf);
  mpz_init(result);
  mpz_init(left);
  mpz_init(right);
  mpz_init(byte);
  mpz_init(mask);
  /* l33t algorithm for byte array to integer */
  for (i = 0; i < 16; i++)
    {
      mpz_set_ui(byte, buf[i]);
      mpz_set_ui(mask, 0xFF);
      mpz_mul_2exp(left, result, 8);
      mpz_and(right, byte, mask);
      mpz_ior(result, left, right);
    }
  mpz_clear(left);
  mpz_clear(right);
  mpz_clear(byte);
  mpz_clear(mask);
  mpz_init_set(*ip_int, result);
  mpz_clear(result);

  return(0);
}

int	i2a_get_ip_type(char *ip_str, t_ip *ip)
{
  int	ret;
  unsigned char buf[sizeof(struct in6_addr)];

  ret = inet_addr(ip_str);
  if (ret != -1)
    ip->version = 4;
  else if (inet_pton(AF_INET6, ip_str, buf) == 1)
    ip->version = 6;
  else
    ip->version = 0;
  return(ip->version);
}

int	i2a_ip_to_integer(char *ip_str, t_ip *ip)
{
  i2a_get_ip_type(ip_str, ip);

  switch (ip->version)
    {
    case 4:
      i2a_ipv4_getint(&ip->v4_ip, ip_str);
      break;

    case 6:
      i2a_ipv6_getint(&ip->v6_ip, ip_str);
      break;

    default:
      printf("bad format\n");
    }
  return(ip->version);
}

int	main(int argc, char *argv[])
{
  t_ip	*ip_data;
  char	*asn_str = NULL;

  if (argc != 2)
    usage(argv[0]);
  if ((ip_data = malloc(sizeof(t_ip))) == NULL)
    {
      printf("malloc error\n");
      exit(EXIT_FAILURE);
    }

  i2a_ip_to_integer(argv[1], ip_data);
  if (ip_data->version == 4)
    asn_str = i2a_ipv4_getasn(ip_data->v4_ip);
  else if (ip_data->version == 6)
    asn_str = i2a_ipv6_getasn(&ip_data->v6_ip);
  i2a_print_results(argv[1], asn_str);

  free(asn_str);
  free(ip_data);
  return(0);
}
